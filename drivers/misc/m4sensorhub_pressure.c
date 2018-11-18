/*
 *  Copyright (C) 2012 Motorola, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  Adds ability to program periodic interrupts from user space that
 *  can wake the phone out of low power modes.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/input.h>
#include <linux/m4sensorhub.h>
#include <linux/m4sensorhub/MemMapPressureSensor.h>
#include <linux/m4sensorhub/m4sensorhub_registers.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/iio/iio.h>
#include <linux/iio/types.h>
#include <linux/iio/sysfs.h>
#include <linux/iio/events.h>
#include <linux/iio/buffer.h>
#include <linux/iio/kfifo_buf.h>
#include <linux/iio/m4sensorhub/m4sensorhub_pressure.h>

#define m4sensorhub_pressure_DRIVER_NAME	"m4sensorhub_pressure"

struct m4sensorhub_pressure_drvdata {
	struct m4sensorhub_data *p_m4sensorhub;
	int samplerate;
	bool irq_enabled;
	struct platform_device      *pdev;
	struct m4sensorhub_pressure_iio_data read_data;
	struct mutex                mutex;
};

#define DATA_SIZE_IN_BITS  (sizeof(struct m4sensorhub_pressure_iio_data) * 8)

/* We are ADC with 1 channel */
static const struct iio_chan_spec m4sensorhub_pressure_channels[] = {
	{
		.type = IIO_PRESSURE,
		/* Channel has a numeric index of 0 */
		.indexed = 1,
		.channel = 0,

		.scan_index = 0,
		.scan_type = { /* Description of storage in buffer */
			.sign = 'u', /* unsigned */
			.realbits = DATA_SIZE_IN_BITS,
			.storagebits = DATA_SIZE_IN_BITS,
			.shift = 0, /* zero shift */
		},
	},
};


static void m4pressure_isr(enum m4sensorhub_irqs int_event, void *handle)
{
	struct m4sensorhub_pressure_drvdata *p_priv_data = handle;
	struct m4sensorhub_data *p_m4sensorhub = p_priv_data->p_m4sensorhub;
	struct iio_dev *p_iio_dev = platform_get_drvdata(p_priv_data->pdev);
	sPressureData pressure;

	mutex_lock(&(p_priv_data->mutex));

	p_priv_data->read_data.type = PRESSURE_TYPE_EVENT_DATA;
	m4sensorhub_reg_read(p_m4sensorhub,
				M4SH_REG_PRESSURE_PRESSURE,
				(char *)&pressure.pressure);
	m4sensorhub_reg_read(p_m4sensorhub,
				M4SH_REG_PRESSURE_ABSOLUTEALTITUDE,
				(char *)&pressure.absoluteAltitude);

	p_priv_data->read_data.event_data.pressure = pressure.pressure;
	p_priv_data->read_data.event_data.altitude = pressure.absoluteAltitude;
	p_priv_data->read_data.timestamp = ktime_to_ns(ktime_get_boottime());

	iio_push_to_buffers(p_iio_dev,
		(unsigned char *)&(p_priv_data->read_data));

	mutex_unlock(&(p_priv_data->mutex));
}

static void m4pressure_panic_restore(struct m4sensorhub_data *m4sensorhub,
	void *data)
{
	struct m4sensorhub_pressure_drvdata *p_priv_data =
			(struct m4sensorhub_pressure_drvdata *)data;
	int ret;

	mutex_lock(&(p_priv_data->mutex));

	if (p_priv_data->samplerate < 0)
		goto err;

	ret = m4sensorhub_reg_write(p_priv_data->p_m4sensorhub,
			M4SH_REG_PRESSURE_SAMPLERATE,
			(char *)&(p_priv_data->samplerate), m4sh_no_mask);
	if (ret != m4sensorhub_reg_getsize(
			p_priv_data->p_m4sensorhub,
			M4SH_REG_PRESSURE_SAMPLERATE)) {
		pr_err("%s:Unable to set delay\n", __func__);
		goto err;
	}

err:
	mutex_unlock(&(p_priv_data->mutex));
}

static int m4sensorhub_pressure_driver_initcallback(struct init_calldata *p_arg)
{
	struct iio_dev *p_iio_dev = (struct iio_dev *)(p_arg->p_data);
	struct m4sensorhub_data *p_m4sensorhub = p_arg->p_m4sensorhub_data;
	struct m4sensorhub_pressure_drvdata *p_priv_data = iio_priv(p_iio_dev);
	int ret;

	p_priv_data->p_m4sensorhub = p_m4sensorhub;

	ret = m4sensorhub_irq_register(p_m4sensorhub,
		M4SH_NOWAKEIRQ_PRESSURE, m4pressure_isr,
		p_priv_data, 0);
	if (ret < 0) {
		pr_err("%s: Failed to register M4 IRQ.\n", __func__);
		return ret;
	}

	ret = m4sensorhub_panic_register(p_m4sensorhub,
		PANICHDL_PRESSURE_RESTORE,
		m4pressure_panic_restore, p_priv_data);
	if (ret < 0)
		pr_err("%s: Panic registration failed.\n", __func__);

	return 0;
}

/* setdelay */
static ssize_t m4sensorhub_pressure_store_setdelay(struct device *p_dev,
			struct device_attribute *p_attr,
			const char *p_buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(p_dev);
	struct iio_dev *p_iio_dev = platform_get_drvdata(pdev);
	struct m4sensorhub_pressure_drvdata *p_priv_data = iio_priv(p_iio_dev);
	int ret;
	int samplerate;

	ret = kstrtoint(p_buf, 10, &samplerate);
	if (ret < 0)
		return ret;

	if (samplerate < -1) {
		pr_err("%s: non -1 negative sample rate, rejecting\n",
			__func__);
		return -EINVAL;
	}

	mutex_lock(&(p_priv_data->mutex));
	if (samplerate != p_priv_data->samplerate) {
		ret = m4sensorhub_reg_write(p_priv_data->p_m4sensorhub,
				M4SH_REG_PRESSURE_SAMPLERATE,
				(char *)&samplerate, m4sh_no_mask);
		if (ret != m4sensorhub_reg_getsize(
				p_priv_data->p_m4sensorhub,
				M4SH_REG_PRESSURE_SAMPLERATE)) {
			pr_err("%s:Unable to set delay\n", __func__);
			goto err;
		}

		p_priv_data->samplerate = samplerate;
	}

	if (samplerate >= 0) {
		/* Enable the IRQ if necessary */
		if (!(p_priv_data->irq_enabled)) {
			ret = m4sensorhub_irq_enable(
				p_priv_data->p_m4sensorhub,
				M4SH_NOWAKEIRQ_PRESSURE);
			if (ret < 0) {
				pr_err("%s: Failed to enable irq.\n",
					  __func__);
				goto err;
			}
			p_priv_data->irq_enabled = true;
		}
	} else {
		/* Disable the IRQ if necessary */
		if (p_priv_data->irq_enabled) {
			ret = m4sensorhub_irq_disable(
				p_priv_data->p_m4sensorhub,
				M4SH_NOWAKEIRQ_PRESSURE);
			if (ret < 0) {
				pr_err("%s: Failed to disable irq.\n",
					  __func__);
				goto err;
			}
			p_priv_data->irq_enabled = false;
		}
	}

err:
	mutex_unlock(&(p_priv_data->mutex));

	return count;
}

static ssize_t m4sensorhub_pressure_show_setdelay(struct device *p_dev,
				struct device_attribute *p_attr, char *p_buf)
{
	struct platform_device *pdev = to_platform_device(p_dev);
	struct iio_dev *p_iio_dev =
						platform_get_drvdata(pdev);
	struct m4sensorhub_pressure_drvdata *p_priv_data = iio_priv(p_iio_dev);
	int count;

	mutex_lock(&(p_priv_data->mutex));
	count = snprintf(p_buf, PAGE_SIZE, "%d\n", p_priv_data->samplerate);
	mutex_unlock(&(p_priv_data->mutex));

	return count;
}

static IIO_DEVICE_ATTR(setdelay, S_IRUGO | S_IWUSR,
					m4sensorhub_pressure_show_setdelay,
					m4sensorhub_pressure_store_setdelay, 0);

static ssize_t m4sensorhub_pressure_store_flush(struct device *p_dev,
			struct device_attribute *p_attr,
			const char *p_buf, size_t count)
{
	struct platform_device *pdev = to_platform_device(p_dev);
	struct iio_dev *p_iio_dev = platform_get_drvdata(pdev);
	struct m4sensorhub_pressure_drvdata *p_priv_data = iio_priv(p_iio_dev);

	mutex_lock(&(p_priv_data->mutex));
	p_priv_data->read_data.type = PRESSURE_TYPE_EVENT_FLUSH;
	p_priv_data->read_data.timestamp = ktime_to_ns(ktime_get_boottime());

	iio_push_to_buffers(p_iio_dev,
			    (unsigned char *)&(p_priv_data->read_data));

	mutex_unlock(&(p_priv_data->mutex));

	return count;
}

static IIO_DEVICE_ATTR(flush, S_IRUGO | S_IWUSR, NULL,
		       m4sensorhub_pressure_store_flush, 0);

static ssize_t m4sensorhub_pressure_show_iiodata(struct device *p_dev,
				struct device_attribute *p_attr, char *p_buf)
{
	struct platform_device *pdev = to_platform_device(p_dev);
	struct iio_dev *p_iio_dev = platform_get_drvdata(pdev);
	struct m4sensorhub_pressure_drvdata *p_priv_data = iio_priv(p_iio_dev);
	ssize_t size = 0;

	if (p_priv_data->read_data.type == PRESSURE_TYPE_EVENT_DATA) {
		size = snprintf(p_buf, PAGE_SIZE, "Pressure:%d\nAltitude:%d\n",
				p_priv_data->read_data.event_data.pressure,
				p_priv_data->read_data.event_data.altitude);
	} else if (p_priv_data->read_data.type == PRESSURE_TYPE_EVENT_FLUSH) {
		size = snprintf(p_buf, PAGE_SIZE, "Flush Event\n");
	}
	return size;
}
static IIO_DEVICE_ATTR(iiodata, S_IRUGO | S_IWUSR,
					m4sensorhub_pressure_show_iiodata,
					NULL, 0);
#define M4_DEV_ATTR(name) (&iio_dev_attr_##name.dev_attr.attr)

static struct attribute *m4sensorhub_pressure_attributes[] = {
	M4_DEV_ATTR(setdelay),
	M4_DEV_ATTR(flush),
	M4_DEV_ATTR(iiodata),
	NULL
};

static const struct attribute_group m4sensorhub_pressure_group = {
	.attrs = m4sensorhub_pressure_attributes,
};

static const struct iio_info m4sensorhub_pressure_iio_info = {
	.driver_module = THIS_MODULE,
	.attrs = &m4sensorhub_pressure_group,
};

static int m4sensorhub_pressure_setup_buffer(struct iio_dev *p_iio_dev)
{
	struct iio_buffer *p_buffer;
	int ret;
	p_buffer = iio_kfifo_allocate(p_iio_dev);
	if (p_buffer == NULL) {
		pr_err("%s: failed to allocate buffer\n", __func__);
		ret = -ENOMEM;
		return ret;
	}

	p_iio_dev->buffer = p_buffer;

    /* need timestamps */
	p_buffer->scan_timestamp = true;
	ret = iio_buffer_register(p_iio_dev, p_iio_dev->channels,
						p_iio_dev->num_channels);

	if (ret < 0) {
		pr_err("%s: failed to register buffer\n", __func__);
		goto err;
	}
	p_buffer->access->set_bytes_per_datum(p_buffer,
				sizeof(struct m4sensorhub_pressure_iio_data));

	ret = 0;
	return ret;
err:
	iio_kfifo_free(p_buffer);

	return ret;
}

static int m4sensorhub_pressure_probe(struct platform_device *pdev)
{
	int ret = -1;
	struct iio_dev *p_iio_dev;
	struct m4sensorhub_pressure_drvdata *p_priv_data;

	p_iio_dev = iio_device_alloc(
			sizeof(struct m4sensorhub_pressure_drvdata));

	if (p_iio_dev == NULL) {
		pr_err("%s: no mem", __func__);
		ret = -ENOMEM;
		goto err;
	}

	p_priv_data = iio_priv(p_iio_dev);
	p_priv_data->pdev = pdev;
	p_priv_data->samplerate = -1;
	p_priv_data->irq_enabled = false;
	p_priv_data->p_m4sensorhub = NULL;
	mutex_init(&(p_priv_data->mutex));

	platform_set_drvdata(pdev, p_iio_dev);

	p_iio_dev->info = &m4sensorhub_pressure_iio_info;
	p_iio_dev->name = m4sensorhub_pressure_DRIVER_NAME;
	p_iio_dev->modes = INDIO_DIRECT_MODE | INDIO_BUFFER_HARDWARE;
	p_iio_dev->channels = m4sensorhub_pressure_channels;
	p_iio_dev->num_channels = ARRAY_SIZE(m4sensorhub_pressure_channels);

	/* Register the channel with a buffer */
	ret = m4sensorhub_pressure_setup_buffer(p_iio_dev);
	if (ret < 0) {
		pr_err("%s: can't setup buffer", __func__);
		goto cleanup1;
	}

	ret = iio_device_register(p_iio_dev);
	if (ret < 0) {
		pr_err("%s: iio_register failed", __func__);
		goto cleanup2;
	}

	ret = m4sensorhub_register_initcall(
			m4sensorhub_pressure_driver_initcallback,
			p_iio_dev);
	if (ret < 0) {
		pr_err("%s:Register init failed, ret = %d\n", __func__, ret);
		goto cleanup3;
	}

	return 0;
cleanup3:
	iio_device_unregister(p_iio_dev);
cleanup2:
	iio_kfifo_free(p_iio_dev->buffer);
	iio_buffer_unregister(p_iio_dev);
cleanup1:
	iio_device_free(p_iio_dev);
	platform_set_drvdata(pdev, NULL);
err:
	return ret;
}

static int __exit m4sensorhub_pressure_remove(struct platform_device *pdev)
{
	struct iio_dev *p_iio_dev =
						platform_get_drvdata(pdev);
	struct m4sensorhub_pressure_drvdata *p_priv_data = iio_priv(p_iio_dev);

	mutex_lock(&(p_priv_data->mutex));

	if (p_priv_data->irq_enabled) {
		m4sensorhub_irq_disable(p_priv_data->p_m4sensorhub,
			M4SH_NOWAKEIRQ_PRESSURE);
		p_priv_data->irq_enabled = false;
	}
	m4sensorhub_irq_unregister(p_priv_data->p_m4sensorhub,
		M4SH_NOWAKEIRQ_PRESSURE);
	m4sensorhub_unregister_initcall(
				m4sensorhub_pressure_driver_initcallback);

	iio_kfifo_free(p_iio_dev->buffer);
	iio_buffer_unregister(p_iio_dev);
	iio_device_unregister(p_iio_dev);
	mutex_unlock(&(p_priv_data->mutex));
	mutex_destroy(&(p_priv_data->mutex));
	iio_device_free(p_iio_dev);
	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct of_device_id m4sensorhub_pressure_match_tbl[] = {
	{ .compatible = "mot,m4pressure" },
	{},
};

static struct platform_driver m4sensorhub_pressure_driver = {
	.probe		= m4sensorhub_pressure_probe,
	.remove		= __exit_p(m4sensorhub_pressure_remove),
	.shutdown	= NULL,
	.suspend	= NULL,
	.resume		= NULL,
	.driver		= {
		.name	= m4sensorhub_pressure_DRIVER_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(m4sensorhub_pressure_match_tbl),
	},
};

module_platform_driver(m4sensorhub_pressure_driver);

MODULE_ALIAS("platform:m4sensorhub_pressure");
MODULE_DESCRIPTION("M4 Sensor Hub Pressure IIO driver");
MODULE_AUTHOR("Motorola");
MODULE_LICENSE("GPL");
