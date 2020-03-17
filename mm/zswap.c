/*
 * zswap.c - zswap driver file
 *
 * zswap is a backend for frontswap that takes pages that are in the process
 * of being swapped out and attempts to compress and store them in a
 * RAM-based memory pool.  This can result in a significant I/O reduction on
 * the swap device and, in the case where decompressing from RAM is faster
 * than reading from the swap device, can also improve workload performance.
 *
 * Copyright (C) 2012  Seth Jennings <sjenning@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/frontswap.h>
#include <linux/btree.h>
#include <linux/swap.h>
#include <linux/blkdev.h>
#include <linux/swapfile.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/zpool.h>

#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#define CREATE_TRACE_POINTS
#include <trace/events/zswap.h>

/*********************************
* statistics
**********************************/
/* Total bytes used by the compressed storage */
static u64 zswap_pool_total_size;
/* The number of compressed pages currently stored in zswap */
static atomic_t zswap_stored_pages = ATOMIC_INIT(0);

/*
 * The statistics below are not protected from concurrent access for
 * performance reasons so they may not be a 100% accurate.  However,
 * they do provide useful information on roughly how many times a
 * certain event is occurring.
*/

/* Compressed page was too big for the allocator to (optimally) store */
static u64 zswap_reject_compress_poor;
/* Store failed because underlying allocator could not get memory */
static u64 zswap_reject_alloc_fail;
/* Store failed because the entry metadata could not be allocated (rare) */
static u64 zswap_reject_kmemcache_fail;
/* Duplicate store was encountered (rare) */
static u64 zswap_duplicate_entry;

/* The number of zero pages currently stored in zswap */
static atomic_t zswap_zero_pages = ATOMIC_INIT(0);

/*********************************
* tunables
**********************************/
/* Enable/disable zswap (disabled by default, fixed at boot for now) */
static bool zswap_enabled __read_mostly = 1;
module_param_named(enabled, zswap_enabled, bool, 0444);

/* Compressor to be used by zswap (fixed at boot for now) */
#define ZSWAP_COMPRESSOR_DEFAULT "lz4"
static char *zswap_compressor = ZSWAP_COMPRESSOR_DEFAULT;
module_param_named(compressor, zswap_compressor, charp, 0444);

/* Compressed storage to use */
#define ZSWAP_ZPOOL_DEFAULT "zsmalloc"
static char *zswap_zpool_type = ZSWAP_ZPOOL_DEFAULT;
module_param_named(zpool, zswap_zpool_type, charp, 0444);

/* zswap compaction related parameters */
static unsigned int zswap_compaction_interval = 10;
module_param_named(compaction_interval, zswap_compaction_interval, uint, 0644);

static unsigned int zswap_compaction_pages = 2048;
module_param_named(compaction_pages, zswap_compaction_pages, uint, 0644);

/* zpool is shared by all of zswap backend  */
static struct zpool *zswap_pool;

static const gfp_t zswap_gfp = __GFP_NORETRY | __GFP_NOWARN | __GFP_HIGHMEM | __GFP_MOVABLE;

/*********************************
* compression functions
**********************************/
/* per-cpu compression transforms */
static struct crypto_comp * __percpu *zswap_comp_pcpu_tfms;

enum comp_op {
	ZSWAP_COMPOP_COMPRESS,
	ZSWAP_COMPOP_DECOMPRESS
};

static int zswap_comp_op(enum comp_op op, const u8 *src, unsigned int slen,
				u8 *dst, unsigned int *dlen)
{
	struct crypto_comp *tfm;
	int ret;

	tfm = *per_cpu_ptr(zswap_comp_pcpu_tfms, get_cpu());
	switch (op) {
	case ZSWAP_COMPOP_COMPRESS:
		ret = crypto_comp_compress(tfm, src, slen, dst, dlen);
		break;
	case ZSWAP_COMPOP_DECOMPRESS:
		ret = crypto_comp_decompress(tfm, src, slen, dst, dlen);
		break;
	default:
		ret = -EINVAL;
	}

	put_cpu();
	return ret;
}

static int __init zswap_comp_init(void)
{
	if (!crypto_has_comp(zswap_compressor, 0, 0)) {
		pr_info("%s compressor not available\n", zswap_compressor);
		/* fall back to default compressor */
		zswap_compressor = ZSWAP_COMPRESSOR_DEFAULT;
		if (!crypto_has_comp(zswap_compressor, 0, 0))
			/* can't even load the default compressor */
			return -ENODEV;
	}
	pr_info("using %s compressor\n", zswap_compressor);

	/* alloc percpu transforms */
	zswap_comp_pcpu_tfms = alloc_percpu(struct crypto_comp *);
	if (!zswap_comp_pcpu_tfms)
		return -ENOMEM;
	return 0;
}

static void __init zswap_comp_exit(void)
{
	/* free percpu transforms */
	free_percpu(zswap_comp_pcpu_tfms);
}

/*********************************
* data structures
**********************************/
/*
 * struct zswap_entry
 *
 * This structure contains the metadata for tracking a single compressed
 * page within zswap.
 *
 * refcount - the number of outstanding reference to the entry. This is needed
 *            to protect against premature freeing of the entry by code
 *            concurrent calls to load, invalidate, and writeback.  The lock
 *            for the zswap_tree structure that contains the entry must
 *            be held while changing the refcount.  Since the lock must
 *            be held, there is no reason to also make refcount atomic.
 * offset - the swap offset for the entry.  Index into the red-black tree.
 * handle - zpool allocation handle that stores the compressed page data
 * length - the length in bytes of the compressed page data.  Needed during
 *          decompression
 * zero_flag - the flag indicating the page for the zswap_entry is a zero page.
 *            zswap does not store the page during compression.
 *            It memsets the page with 0 during decompression.
 */
struct zswap_entry {
	pgoff_t offset;
	int refcount;
	unsigned int length;
	unsigned long handle;
	unsigned char zero_flag;
};

/*
 * The tree lock in the zswap_tree struct protects a few things:
 * - the tree
 * - the refcount field of each entry in the tree
 */
struct zswap_tree {
	struct btree_head head;
	spinlock_t lock;
};

static struct zswap_tree *zswap_trees[MAX_SWAPFILES];

/*********************************
* zswap entry functions
**********************************/
static struct kmem_cache *zswap_entry_cache;

static int __init zswap_entry_cache_create(void)
{
	zswap_entry_cache = KMEM_CACHE(zswap_entry, 0);
	return zswap_entry_cache == NULL;
}

static void __init zswap_entry_cache_destroy(void)
{
	kmem_cache_destroy(zswap_entry_cache);
}

static struct zswap_entry *zswap_entry_cache_alloc(gfp_t gfp)
{
	struct zswap_entry *entry;
	entry = kmem_cache_alloc(zswap_entry_cache, gfp);
	if (unlikely(!entry))
		return NULL;
	entry->refcount = 1;
	entry->zero_flag = 0;
	return entry;
}

static void zswap_entry_cache_free(struct zswap_entry *entry)
{
	kmem_cache_free(zswap_entry_cache, entry);
}

/*********************************
* btree functions
**********************************/
static struct btree_geo *btree_pgofft_geo;

static struct zswap_entry *zswap_search(struct btree_head *head, pgoff_t offset)
{
	return btree_lookup(head, btree_pgofft_geo, &offset);
}

static void zswap_erase(struct btree_head *head, struct zswap_entry *entry)
{
	btree_remove(head, btree_pgofft_geo, &entry->offset);
}

/*
 * Carries out the common pattern of freeing and entry's zpool allocation,
 * freeing the entry itself, and decrementing the number of stored pages.
 */
static void zswap_free_entry(struct zswap_entry *entry)
{
	if (entry->zero_flag == 1) {
		atomic_dec(&zswap_zero_pages);
		goto zeropage_out;
	}
	zpool_free(zswap_pool, entry->handle);
zeropage_out:
	zswap_entry_cache_free(entry);
	atomic_dec(&zswap_stored_pages);
	zswap_pool_total_size = zpool_get_total_size(zswap_pool);
}

/* caller must hold the tree lock */
static void zswap_entry_get(struct zswap_entry *entry)
{
	entry->refcount++;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
static void zswap_entry_put(struct btree_head *head,
			struct zswap_entry *entry)
{
	int refcount = --entry->refcount;

	BUG_ON(refcount < 0);
	if (refcount == 0) {
		zswap_erase(head, entry);
		zswap_free_entry(entry);
	}
}

static int zswap_insert_or_replace(struct btree_head *head,
				struct zswap_entry *entry)
{
	struct zswap_entry *old;

	do {
		old = btree_remove(head, btree_pgofft_geo, &entry->offset);
		if (old) {
			zswap_duplicate_entry++;
			zswap_entry_put(head, old);
		}
	} while (old);
	return btree_insert(head, btree_pgofft_geo, &entry->offset, entry,
			GFP_ATOMIC);
}

/* caller must hold the tree lock */
static struct zswap_entry *zswap_entry_find_get(struct btree_head *head,
				pgoff_t offset)
{
	struct zswap_entry *entry = NULL;

	entry = zswap_search(head, offset);
	if (entry)
		zswap_entry_get(entry);

	return entry;
}

/*********************************
* per-cpu code
**********************************/
static DEFINE_PER_CPU(u8 *, zswap_dstmem);

static int __zswap_cpu_notifier(unsigned long action, unsigned long cpu)
{
	struct crypto_comp *tfm;
	u8 *dst;

	switch (action) {
	case CPU_UP_PREPARE:
		tfm = crypto_alloc_comp(zswap_compressor, 0, 0);
		if (IS_ERR(tfm)) {
			pr_err("can't allocate compressor transform\n");
			return NOTIFY_BAD;
		}
		*per_cpu_ptr(zswap_comp_pcpu_tfms, cpu) = tfm;
		dst = kmalloc_node(PAGE_SIZE * 2, GFP_KERNEL, cpu_to_node(cpu));
		if (!dst) {
			pr_err("can't allocate compressor buffer\n");
			crypto_free_comp(tfm);
			*per_cpu_ptr(zswap_comp_pcpu_tfms, cpu) = NULL;
			return NOTIFY_BAD;
		}
		per_cpu(zswap_dstmem, cpu) = dst;
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		tfm = *per_cpu_ptr(zswap_comp_pcpu_tfms, cpu);
		if (tfm) {
			crypto_free_comp(tfm);
			*per_cpu_ptr(zswap_comp_pcpu_tfms, cpu) = NULL;
		}
		dst = per_cpu(zswap_dstmem, cpu);
		kfree(dst);
		per_cpu(zswap_dstmem, cpu) = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static int zswap_cpu_notifier(struct notifier_block *nb,
				unsigned long action, void *pcpu)
{
	unsigned long cpu = (unsigned long)pcpu;
	return __zswap_cpu_notifier(action, cpu);
}

static struct notifier_block zswap_cpu_notifier_block = {
	.notifier_call = zswap_cpu_notifier
};

static int __init zswap_cpu_init(void)
{
	unsigned long cpu;

	cpu_notifier_register_begin();
	for_each_online_cpu(cpu)
		if (__zswap_cpu_notifier(CPU_UP_PREPARE, cpu) != NOTIFY_OK)
			goto cleanup;
	__register_cpu_notifier(&zswap_cpu_notifier_block);
	cpu_notifier_register_done();
	return 0;

cleanup:
	for_each_online_cpu(cpu)
		__zswap_cpu_notifier(CPU_UP_CANCELED, cpu);
	cpu_notifier_register_done();
	return -ENOMEM;
}

/*********************************
* helpers
**********************************/
enum zswap_pool_status {
	ZSWAP_POOL_MAX,
	ZSWAP_POOL_HIGH,
	ZSWAP_POOL_LOW,
};

static int page_zero_filled(void *ptr)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

/*********************************
* frontswap hooks
**********************************/
/* attempts to compress and store an single page */
static int zswap_frontswap_store(unsigned type, pgoff_t offset,
				struct page *page)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry;
	int ret;
	unsigned int dlen = PAGE_SIZE, len;
	unsigned long handle;
	char *buf;
	u8 *src, *dst;

	if (!tree) {
		ret = -ENODEV;
		goto reject;
	}

	/* if this page got EIO on pageout before, give up immediately */
	if (PageError(page)) {
		ret = -ENOMEM;
		goto reject;
	}

	/* allocate entry */
	entry = zswap_entry_cache_alloc(GFP_KERNEL);
	if (unlikely(!entry)) {
		zswap_reject_kmemcache_fail++;
		ret = -ENOMEM;
		goto reject;
	}

	/* compress */
	src = kmap_atomic(page);
	if (page_zero_filled(src)) {
		atomic_inc(&zswap_zero_pages);
		entry->zero_flag = 1;
		kunmap_atomic(src);

		handle = 0;
		dlen = PAGE_SIZE;
		goto zeropage_out;
	}
	dst = get_cpu_var(zswap_dstmem);

	ret = zswap_comp_op(ZSWAP_COMPOP_COMPRESS, src, PAGE_SIZE, dst, &dlen);
	kunmap_atomic(src);
	if (ret) {
		ret = -EINVAL;
		goto freepage;
	}

	/* store */
	if (dlen > PAGE_SIZE)
		dlen = PAGE_SIZE;
	len = dlen;
	ret = zpool_malloc(zswap_pool, len, zswap_gfp, &handle);
	if (ret == -ENOSPC) {
		zswap_reject_compress_poor++;
		goto freepage;
	}
	if (ret) {
		zswap_reject_alloc_fail++;
		goto freepage;
	}
	buf = (u8 *)zpool_map_handle(zswap_pool, handle, ZPOOL_MM_RW);
	if (dlen == PAGE_SIZE) {
		src = kmap_atomic(page);
		copy_page(buf, src);
		kunmap_atomic(src);
	} else
		memcpy(buf, dst, dlen);

	zpool_unmap_handle(zswap_pool, handle);
	put_cpu_var(zswap_dstmem);

zeropage_out:
	/* populate entry */
	entry->offset = offset;
	entry->handle = handle;
	entry->length = dlen;

	/* map */
	spin_lock(&tree->lock);
	ret = zswap_insert_or_replace(&tree->head, entry);
	spin_unlock(&tree->lock);
	if (ret < 0)  {
		zswap_reject_alloc_fail++;
		goto freepage;
	}

	/* update stats */
	atomic_inc(&zswap_stored_pages);
	zswap_pool_total_size = zpool_get_total_size(zswap_pool);

	return 0;

freepage:
	put_cpu_var(zswap_dstmem);
	zswap_entry_cache_free(entry);
reject:
	return ret;
}

static void hexdump(char *title, u8 *data, int len)
{
	int i;

	printk("%s: length = %d\n", title, len);
	for (i = 0; i < len; i++) {
		printk("%02x ", data[i]);
		if ((i & 0xf) == 0xf)
			printk("\n");
	}
	printk("\n");
}

/*
 * returns 0 if the page was successfully decompressed
 * return -1 on entry not found or error
*/
static int zswap_frontswap_load(unsigned type, pgoff_t offset,
				struct page *page)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry;
	u8 *src, *dst;
	unsigned int dlen;
	int ret = 0;

	/* find */
	spin_lock(&tree->lock);
	entry = zswap_entry_find_get(&tree->head, offset);
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		return -1;
	}
	spin_unlock(&tree->lock);

	if (entry->zero_flag == 1) {
		dst = kmap_atomic(page);
		memset(dst, 0, PAGE_SIZE);
		kunmap_atomic(dst);
		goto zeropage_out;
	}

	/* decompress */
	dlen = PAGE_SIZE;
	src = (u8 *)zpool_map_handle(zswap_pool, entry->handle,
			ZPOOL_MM_RO);
	dst = kmap_atomic(page);
	if (entry->length == PAGE_SIZE)
		copy_page(dst, src);
	else
		ret = zswap_comp_op(ZSWAP_COMPOP_DECOMPRESS, src, entry->length,
			dst, &dlen);

	if (ret) {
		hexdump("src buffer", src, entry->length);
		if (dlen)
			hexdump("dest buffer", dst, dlen);
		printk("zswap_comp_op returned %d\n", ret);
	}

	kunmap_atomic(dst);
	zpool_unmap_handle(zswap_pool, entry->handle);
	BUG_ON(ret);

zeropage_out:
	spin_lock(&tree->lock);
	zswap_entry_put(&tree->head, entry);
	spin_unlock(&tree->lock);

	return 0;
}

void zswap_compact(void);
int sysctl_zswap_compact;
int sysctl_zswap_compaction_handler(struct ctl_table *table, int write,
			void __user *buffer, size_t *length, loff_t *ppos)
{
	if (write)
		zswap_compact();
	else
		proc_dointvec(table, write, buffer, length, ppos);

	return 0;
}

static void zswap_compact_zpool(struct work_struct *work)
{
	zswap_compact();
}
static DECLARE_WORK(zswap_compaction_work, zswap_compact_zpool);

void zswap_compact(void) {
	if (!zswap_pool)
		return;

	sysctl_zswap_compact++;
	zpool_compact(zswap_pool);
	pr_info("zswap_compact: (%d times so far)\n",
		sysctl_zswap_compact);
}

/* frees an entry in zswap */
static void zswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry;
#ifdef CONFIG_ZSWAP_COMPACTION
	static unsigned long resume = 0;
#endif

	/* find */
	spin_lock(&tree->lock);
	entry = zswap_search(&tree->head, offset);
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		return;
	}

	/* remove from tree */
	zswap_erase(&tree->head, entry);

	/* drop the initial reference from entry creation */
	zswap_entry_put(&tree->head, entry);

	spin_unlock(&tree->lock);

#ifdef CONFIG_ZSWAP_COMPACTION
	if (time_is_before_jiffies(resume) &&
		!work_pending(&zswap_compaction_work) &&
		zpool_compactable(zswap_pool, zswap_compaction_pages)) {
		resume = jiffies + zswap_compaction_interval * HZ;
		schedule_work(&zswap_compaction_work);
	}
#endif
}

void do_free_entry(void *elem, unsigned long opaque, unsigned long *key,
		size_t index, void *func2)
{
	struct zswap_entry *entry = elem;
	zswap_free_entry(entry);
}

/* frees all zswap entries for the given swap type */
static void zswap_frontswap_invalidate_area(unsigned type)
{
	struct zswap_tree *tree = zswap_trees[type];

	if (!tree)
		return;

	/* walk the tree and free everything */
	spin_lock(&tree->lock);
	btree_visitor(&tree->head, btree_pgofft_geo, 0, do_free_entry, NULL);
	btree_destroy(&tree->head);
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees[type] = NULL;
}

static void zswap_frontswap_init(unsigned type)
{
	struct zswap_tree *tree;

	tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);
	if (!tree) {
		pr_err("alloc failed, zswap disabled for swap type %d\n", type);
		return;
	}
	if (btree_init(&tree->head) < 0) {
		pr_err("couldn't init the tree head\n");
		kfree(tree);
		return;
	}
	spin_lock_init(&tree->lock);
	zswap_trees[type] = tree;
}

static struct frontswap_ops zswap_frontswap_ops = {
	.store = zswap_frontswap_store,
	.load = zswap_frontswap_load,
	.invalidate_page = zswap_frontswap_invalidate_page,
	.invalidate_area = zswap_frontswap_invalidate_area,
	.init = zswap_frontswap_init
};

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *zswap_debugfs_root;

static int __init zswap_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zswap_debugfs_root = debugfs_create_dir("zswap", NULL);
	if (!zswap_debugfs_root)
		return -ENOMEM;

	debugfs_create_u64("reject_alloc_fail", S_IRUGO,
			zswap_debugfs_root, &zswap_reject_alloc_fail);
	debugfs_create_u64("reject_kmemcache_fail", S_IRUGO,
			zswap_debugfs_root, &zswap_reject_kmemcache_fail);
	debugfs_create_u64("reject_compress_poor", S_IRUGO,
			zswap_debugfs_root, &zswap_reject_compress_poor);
	debugfs_create_u64("duplicate_entry", S_IRUGO,
			zswap_debugfs_root, &zswap_duplicate_entry);
	debugfs_create_u64("pool_total_size", S_IRUGO,
			zswap_debugfs_root, &zswap_pool_total_size);
	debugfs_create_atomic_t("stored_pages", S_IRUGO,
			zswap_debugfs_root, &zswap_stored_pages);
	debugfs_create_atomic_t("zero_pages", S_IRUGO,
			zswap_debugfs_root, &zswap_zero_pages);

	return 0;
}

static void __exit zswap_debugfs_exit(void)
{
	debugfs_remove_recursive(zswap_debugfs_root);
}
#else
static int __init zswap_debugfs_init(void)
{
	return 0;
}

static void __exit zswap_debugfs_exit(void) { }
#endif

/*********************************
* module init and exit
**********************************/
static int __init init_zswap(void)
{
	if (!zswap_enabled)
		return 0;

	pr_info("loading zswap\n");

	zswap_pool = zpool_create_pool(zswap_zpool_type, "zswap", zswap_gfp, NULL);
	if (!zswap_pool && strcmp(zswap_zpool_type, ZSWAP_ZPOOL_DEFAULT)) {
		pr_info("%s zpool not available\n", zswap_zpool_type);
		zswap_zpool_type = ZSWAP_ZPOOL_DEFAULT;
		zswap_pool = zpool_create_pool(zswap_zpool_type, "zswap", zswap_gfp, NULL);
	}
	if (!zswap_pool) {
		pr_err("%s zpool not available\n", zswap_zpool_type);
		pr_err("zpool creation failed\n");
		goto error;
	}
	pr_info("using %s pool\n", zswap_zpool_type);

	if (sizeof(pgoff_t) == 8)
		btree_pgofft_geo = &btree_geo64;
	else
		btree_pgofft_geo = &btree_geo32;

	if (zswap_entry_cache_create()) {
		pr_err("entry cache creation failed\n");
		goto cachefail;
	}
	if (zswap_comp_init()) {
		pr_err("compressor initialization failed\n");
		goto compfail;
	}
	if (zswap_cpu_init()) {
		pr_err("per-cpu initialization failed\n");
		goto pcpufail;
	}

	frontswap_register_ops(&zswap_frontswap_ops);
	if (zswap_debugfs_init())
		pr_warn("debugfs initialization failed\n");
	return 0;
pcpufail:
	zswap_comp_exit();
compfail:
	zswap_entry_cache_destroy();
cachefail:
	zpool_destroy_pool(zswap_pool);
error:
	return -ENOMEM;
}
/* must be late so crypto has time to come up */
late_initcall(init_zswap);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seth Jennings <sjenning@linux.vnet.ibm.com>");
MODULE_DESCRIPTION("Compressed cache for swap pages");
