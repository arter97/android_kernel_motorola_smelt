/*
 * Fuel gauge driver for Maxim 17042 / 8966 / 8997
 *  Note that Maxim 8966 and 8997 are mfd and this is its subdevice.
 *
 * Copyright (C) 2011 Samsung Electronics
 * MyungJoo Ham <myungjoo.ham@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * This driver is based on max17040_battery.c
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/pm.h>
#include <linux/mod_devicetable.h>
#include <linux/power_supply.h>
#include <linux/power/max17042_battery.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/debugfs.h>

/* Status register bits */
#define STATUS_POR_BIT         (1 << 1)
#define STATUS_BST_BIT         (1 << 3)
#define STATUS_TMN_BIT         (1 << 9)
#define STATUS_SMN_BIT         (1 << 10)
#define STATUS_BI_BIT          (1 << 11)
#define STATUS_VMX_BIT         (1 << 12)
#define STATUS_TMX_BIT         (1 << 13)
#define STATUS_SMX_BIT         (1 << 14)
#define STATUS_BR_BIT          (1 << 15)

/* Interrupt mask bits */
#define CONFIG_ALRT_BIT_ENBL	(1 << 2)
#define CONFIG_VS_BIT_ENBL		(1 << 12)
#define CONFIG_TS_BIT_ENBL		(1 << 13)
#define CONFIG_SS_BIT_ENBL		(1 << 14)
#define CONFIG_STICK_ALL_ENBL   (CONFIG_VS_BIT_ENBL | \
CONFIG_TS_BIT_ENBL | CONFIG_SS_BIT_ENBL)
#define VFSOC0_LOCK		0x0000
#define VFSOC0_UNLOCK	0x0080
#define MODEL_UNLOCK1	0X0059
#define MODEL_UNLOCK2	0X00C4
#define MODEL_LOCK1		0X0000
#define MODEL_LOCK2		0X0000

#define MAX17042_INIT_NUM_CYCLES	160
#define MAX17047_INIT_NUM_CYCLES	96

#define MAX17042_dQ_ACC_DIV	4
#define MAX17047_dQ_ACC_DIV	16

#define MAX17042_dP_ACC_200	0x3200
#define MAX17047_dP_ACC_200	0x0C80

#define MAX17042_IC_VERSION	0x0092
#define MAX17047_IC_VERSION	0x00AC	/* same for max17050 */

#define MAX17042_AGE_DIV	256

#define INIT_DATA_PROPERTY		"maxim,regs-init-data"
#define CONFIG_NODE			"maxim,configuration"
#define VERSION_PROPERTY		"version"
#define CONFIG_PROPERTY			"config"
#define FULL_SOC_THRESH_PROPERTY	"full_soc_thresh"
#define DESIGN_CAP_PROPERTY		"design_cap"
#define ICHGT_TERM_PROPERTY		"ichgt_term"
#define LEARN_CFG_PROPERTY		"learn_cfg"
#define FILTER_CFG_PROPERTY		"filter_cfg"
#define RELAX_CFG_PROPERTY		"relax_cfg"
#define FULLCAP_PROPERTY		"fullcap"
#define FULLCAPNOM_PROPERTY		"fullcapnom"
#define QRTBL00_PROPERTY		"qrtbl00"
#define QRTBL10_PROPERTY		"qrtbl10"
#define QRTBL20_PROPERTY		"qrtbl20"
#define QRTBL30_PROPERTY		"qrtbl30"
#define RCOMP0_PROPERTY			"rcomp0"
#define TCOMPC0_PROPERTY		"tcompc0"
#define CELL_CHAR_TBL_PROPERTY		"maxim,cell-char-tbl"
#define TGAIN_PROPERTY			"tgain"
#define TOFF_PROPERTY			"toff"
#define TEMP_CONV_NODE			"maxim,temp-conv"
#define RESULT_PROPERTY			"result"
#define START_PROPERTY			"start"

/* we need to set the alert threshold to a default value
   before powerlib calls into the driver */
#define DEFAULT_ALERT_THRESHOLD	1

struct max17042_chip {
	struct i2c_client *client;
	struct power_supply battery;
	enum max170xx_chip_type chip_type;
	struct max17042_platform_data *pdata;
	struct work_struct work;
	int    init_complete;
	u16 alert_threshold;
#ifdef CONFIG_BATTERY_MAX17042_DEBUGFS
	struct dentry *debugfs_root;
	u8 debugfs_addr;
	u8 debugfs_capacity;
#endif
};

#ifdef CONFIG_OF
const char *get_dts_batt_id(struct device *dev)
{
	int lenp;
	const char *retval = NULL;
	struct device_node *n = of_find_node_by_path("/chosen");

	if (n) {
		retval = of_get_property(n, "batt-id", &lenp);
		if (!retval || !lenp) {
			dev_info(dev, "%s: could not get property\n", __func__);
			retval = NULL;
		}
		of_node_put(n);
	}

	return retval;
}
#else
# define get_dts_batt_id(dev) (NULL)
#endif

static int max17042_write_reg(struct i2c_client *client, u8 reg, u16 value)
{
	int ret = i2c_smbus_write_word_data(client, reg, value);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

static int max17042_read_reg(struct i2c_client *client, u8 reg)
{
	int ret = i2c_smbus_read_word_data(client, reg);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

static void max17042_set_reg(struct i2c_client *client,
			     struct max17042_reg_data *data, int size)
{
	int i;

	for (i = 0; i < size; i++)
		max17042_write_reg(client, data[i].addr, data[i].data);
}

static enum power_supply_property max17042_battery_props[] = {
	POWER_SUPPLY_PROP_PRESENT,
	POWER_SUPPLY_PROP_CYCLE_COUNT,
	POWER_SUPPLY_PROP_VOLTAGE_MAX,
	POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN,
	POWER_SUPPLY_PROP_VOLTAGE_NOW,
	POWER_SUPPLY_PROP_VOLTAGE_AVG,
	POWER_SUPPLY_PROP_VOLTAGE_OCV,
	POWER_SUPPLY_PROP_CAPACITY,
	POWER_SUPPLY_PROP_CHARGE_FULL,
	POWER_SUPPLY_PROP_CHARGE_COUNTER,
	POWER_SUPPLY_PROP_TEMP,
	POWER_SUPPLY_PROP_CURRENT_NOW,
	POWER_SUPPLY_PROP_CURRENT_AVG,
	POWER_SUPPLY_PROP_STATUS
};

/* input and output temperature is in deci-centigrade */
static int max17042_conv_temp(struct max17042_temp_conv *conv, int t)
{
	int i; /* conversion table index */
	s16 *r = conv->result;
	int dt;

	/*
	 * conv->result[0] corresponds to conv->start temp, conv->result[1] to
	 * conv->start + 1 temp, etc. Find index to the conv->result table for
	 * t to be between index and index + 1 temperatures.
	 */
	i = t / 10 - conv->start; /* t is in 1/10th C, conv->start is in C */
	if (t < 0)
		i -= 1;

	/* Interpolate linearly if index and index + 1 are within the table */
	if (i < 0) {
		return r[0];
	} else if (i >= conv->num_result - 1) {
		return r[conv->num_result - 1];
	} else {
		dt = t - (conv->start + i) * 10; /* in 1/10th C */
		return r[i] + (r[i + 1] - r[i]) * dt / 10;
	}
}

static int max17042_get_property(struct power_supply *psy,
			    enum power_supply_property psp,
			    union power_supply_propval *val)
{
	struct max17042_chip *chip = container_of(psy,
				struct max17042_chip, battery);
	int ret;
	u64 data64;

	if (!chip->init_complete)
		return -EAGAIN;

	switch (psp) {
	case POWER_SUPPLY_PROP_PRESENT:
		ret = max17042_read_reg(chip->client, MAX17042_STATUS);
		if (ret < 0)
			return ret;

		if (ret & MAX17042_STATUS_BattAbsent)
			val->intval = 0;
		else
			val->intval = 1;
		break;
	case POWER_SUPPLY_PROP_CYCLE_COUNT:
		ret = max17042_read_reg(chip->client, MAX17042_Cycles);
		if (ret < 0)
			return ret;

		val->intval = ret;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MAX:
		ret = max17042_read_reg(chip->client, MAX17042_MinMaxVolt);
		if (ret < 0)
			return ret;

		val->intval = ret >> 8;
		val->intval *= 20000; /* Units of LSB = 20mV */
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN:
		if (chip->chip_type == MAX17042)
			ret = max17042_read_reg(chip->client, MAX17042_V_empty);
		else
			ret = max17042_read_reg(chip->client, MAX17047_V_empty);
		if (ret < 0)
			return ret;

		val->intval = ret >> 7;
		val->intval *= 10000; /* Units of LSB = 10mV */
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_NOW:
		ret = max17042_read_reg(chip->client, MAX17042_VCELL);
		if (ret < 0)
			return ret;

		val->intval = ret * 625 / 8;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_AVG:
		ret = max17042_read_reg(chip->client, MAX17042_AvgVCELL);
		if (ret < 0)
			return ret;

		val->intval = ret * 625 / 8;
		break;
	case POWER_SUPPLY_PROP_VOLTAGE_OCV:
		ret = max17042_read_reg(chip->client, MAX17042_OCVInternal);
		if (ret < 0)
			return ret;

		val->intval = ret * 625 / 8;
		break;
	case POWER_SUPPLY_PROP_CAPACITY:
#ifdef CONFIG_BATTERY_MAX17042_DEBUGFS
		if (chip->debugfs_capacity != 0xFF) {
			val->intval = chip->debugfs_capacity;
			break;
		}
#endif
		ret = max17042_read_reg(chip->client, MAX17042_RepSOC);
		if (ret < 0)
			return ret;

		val->intval = ret >> 8;
		break;
	case POWER_SUPPLY_PROP_CHARGE_FULL:
		ret = max17042_read_reg(chip->client, MAX17042_FullCAP);
		if (ret < 0)
			return ret;

		data64 = ret * 5000000ll;
		do_div(data64, chip->pdata->r_sns);
		val->intval = data64;
		break;
	case POWER_SUPPLY_PROP_CHARGE_COUNTER:
		ret = max17042_read_reg(chip->client, MAX17042_QH);
		if (ret < 0)
			return ret;

		val->intval = ret * 1000 / 2;
		break;
	case POWER_SUPPLY_PROP_TEMP:
		ret = max17042_read_reg(chip->client, MAX17042_TEMP);
		if (ret < 0)
			return ret;

		val->intval = sign_extend32(ret, 15);

		/* The value is converted into deci-centigrade scale */
		/* Units of LSB = 1 / 256 degree Celsius */
		val->intval = val->intval * 10 / 256;

		/* Convert IC temp to "real" temp */
		if (chip->pdata->tcnv)
			val->intval = max17042_conv_temp(chip->pdata->tcnv,
							 val->intval);
		break;
	case POWER_SUPPLY_PROP_CURRENT_NOW:
		if (chip->pdata->enable_current_sense) {
			ret = max17042_read_reg(chip->client, MAX17042_Current);
			if (ret < 0)
				return ret;

			val->intval = sign_extend32(ret, 15);
			val->intval *= 1562500 / chip->pdata->r_sns;
		} else {
			return -EINVAL;
		}
		break;
	case POWER_SUPPLY_PROP_CURRENT_AVG:
		if (chip->pdata->enable_current_sense) {
			ret = max17042_read_reg(chip->client,
						MAX17042_AvgCurrent);
			if (ret < 0)
				return ret;

			val->intval = sign_extend32(ret, 15);
			val->intval *= 1562500 / chip->pdata->r_sns;
		} else {
			return -EINVAL;
		}
		break;
	case POWER_SUPPLY_PROP_STATUS:
			if (power_supply_am_i_supplied(psy))
				val->intval = POWER_SUPPLY_STATUS_CHARGING;
			else
				val->intval = POWER_SUPPLY_STATUS_DISCHARGING;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int max17042_write_verify_reg(struct i2c_client *client,
				u8 reg, u16 value)
{
	int retries = 8;
	int ret;
	u16 read_value;

	do {
		ret = i2c_smbus_write_word_data(client, reg, value);
		read_value =  max17042_read_reg(client, reg);
		if (read_value != value) {
			ret = -EIO;
			retries--;
		}
	} while (retries && read_value != value);

	if (ret < 0)
		dev_err(&client->dev, "%s: err %d\n", __func__, ret);

	return ret;
}

static inline void max17042_override_por(
	struct i2c_client *client, u8 reg, u16 value)
{
	if (value)
		max17042_write_reg(client, reg, value);
}

static inline void max10742_unlock_model(struct max17042_chip *chip)
{
	struct i2c_client *client = chip->client;
	max17042_write_reg(client, MAX17042_MLOCKReg1, MODEL_UNLOCK1);
	max17042_write_reg(client, MAX17042_MLOCKReg2, MODEL_UNLOCK2);
}

static inline void max10742_lock_model(struct max17042_chip *chip)
{
	struct i2c_client *client = chip->client;
	max17042_write_reg(client, MAX17042_MLOCKReg1, MODEL_LOCK1);
	max17042_write_reg(client, MAX17042_MLOCKReg2, MODEL_LOCK2);
}

static inline void max17042_write_model_data(struct max17042_chip *chip,
					u8 addr, int size)
{
	struct i2c_client *client = chip->client;
	int i;
	for (i = 0; i < size; i++)
		max17042_write_reg(client, addr + i,
				chip->pdata->config_data->cell_char_tbl[i]);
}

static inline void max17042_read_model_data(struct max17042_chip *chip,
					u8 addr, u16 *data, int size)
{
	struct i2c_client *client = chip->client;
	int i;

	for (i = 0; i < size; i++)
		data[i] = max17042_read_reg(client, addr + i);
}

static inline int max17042_model_data_compare(struct max17042_chip *chip,
					u16 *data1, u16 *data2, int size)
{
	int i;

	if (memcmp(data1, data2, size)) {
		dev_err(&chip->client->dev, "%s compare failed\n", __func__);
		for (i = 0; i < size; i++)
			dev_info(&chip->client->dev, "0x%x, 0x%x",
				data1[i], data2[i]);
		dev_info(&chip->client->dev, "\n");
		return -EINVAL;
	}
	return 0;
}

static int max17042_init_model(struct max17042_chip *chip)
{
	int ret;
	int table_size = ARRAY_SIZE(chip->pdata->config_data->cell_char_tbl);
	u16 *temp_data;

	temp_data = kcalloc(table_size, sizeof(*temp_data), GFP_KERNEL);
	if (!temp_data)
		return -ENOMEM;

	max10742_unlock_model(chip);
	max17042_write_model_data(chip, MAX17042_MODELChrTbl,
				table_size);
	max17042_read_model_data(chip, MAX17042_MODELChrTbl, temp_data,
				table_size);

	ret = max17042_model_data_compare(
		chip,
		chip->pdata->config_data->cell_char_tbl,
		temp_data,
		table_size);

	max10742_lock_model(chip);
	kfree(temp_data);

	return ret;
}

static int max17042_verify_model_lock(struct max17042_chip *chip)
{
	int i;
	int table_size = ARRAY_SIZE(chip->pdata->config_data->cell_char_tbl);
	u16 *temp_data;
	int ret = 0;

	temp_data = kcalloc(table_size, sizeof(*temp_data), GFP_KERNEL);
	if (!temp_data)
		return -ENOMEM;

	max17042_read_model_data(chip, MAX17042_MODELChrTbl, temp_data,
				table_size);
	for (i = 0; i < table_size; i++)
		if (temp_data[i])
			ret = -EINVAL;

	kfree(temp_data);
	return ret;
}

static void max17042_write_config_regs(struct max17042_chip *chip)
{
	struct max17042_config_data *config = chip->pdata->config_data;

	max17042_write_reg(chip->client, MAX17042_CONFIG, config->config);
	max17042_write_reg(chip->client, MAX17042_LearnCFG, config->learn_cfg);
	max17042_write_reg(chip->client, MAX17042_FilterCFG,
			config->filter_cfg);
	max17042_write_reg(chip->client, MAX17042_RelaxCFG, config->relax_cfg);
	if (chip->chip_type == MAX17047)
		max17042_write_reg(chip->client, MAX17047_FullSOCThr,
						config->full_soc_thresh);
}

static void  max17042_write_custom_regs(struct max17042_chip *chip)
{
	struct max17042_config_data *config = chip->pdata->config_data;

	max17042_write_verify_reg(chip->client, MAX17042_RCOMP0,
				config->rcomp0);
	max17042_write_verify_reg(chip->client, MAX17042_TempCo,
				config->tcompc0);
	max17042_write_verify_reg(chip->client, MAX17042_ICHGTerm,
				config->ichgt_term);
	if (chip->chip_type == MAX17042) {
		max17042_write_reg(chip->client, MAX17042_EmptyTempCo,
					config->empty_tempco);
		max17042_write_verify_reg(chip->client, MAX17042_K_empty0,
					config->kempty0);
	} else {
		max17042_write_verify_reg(chip->client, MAX17047_QRTbl00,
						config->qrtbl00);
		max17042_write_verify_reg(chip->client, MAX17047_QRTbl10,
						config->qrtbl10);
		max17042_write_verify_reg(chip->client, MAX17047_QRTbl20,
						config->qrtbl20);
		max17042_write_verify_reg(chip->client, MAX17047_QRTbl30,
						config->qrtbl30);
	}
}

static void max17042_update_capacity_regs(struct max17042_chip *chip)
{
	struct max17042_config_data *config = chip->pdata->config_data;

	max17042_write_verify_reg(chip->client, MAX17042_FullCAP,
				config->fullcap);
	max17042_write_reg(chip->client, MAX17042_DesignCap,
			config->design_cap);
	max17042_write_verify_reg(chip->client, MAX17042_FullCAPNom,
				config->fullcapnom);
}

static void max17042_reset_vfsoc0_reg(struct max17042_chip *chip)
{
	u16 vfSoc;

	vfSoc = max17042_read_reg(chip->client, MAX17042_VFSOC);
	max17042_write_reg(chip->client, MAX17042_VFSOC0Enable, VFSOC0_UNLOCK);
	max17042_write_verify_reg(chip->client, MAX17042_VFSOC0, vfSoc);
	max17042_write_reg(chip->client, MAX17042_VFSOC0Enable, VFSOC0_LOCK);
}

static void max17042_advance_to_coulomb_counter_mode(struct max17042_chip *chip)
{
	u16 value = (chip->chip_type == MAX17042 ?
			MAX17042_INIT_NUM_CYCLES : MAX17047_INIT_NUM_CYCLES);
	max17042_write_verify_reg(chip->client, MAX17042_Cycles, value);
}

static void max17042_load_new_capacity_params(struct max17042_chip *chip)
{
	u16 rep_cap, dq_acc, vfSoc;
	u32 rem_cap;
	u16 dQ_ACC_DIV = (chip->chip_type == MAX17042 ?
				MAX17042_dQ_ACC_DIV : MAX17047_dQ_ACC_DIV);
	u16 dP_ACC_200 = (chip->chip_type == MAX17042 ?
				MAX17042_dP_ACC_200 : MAX17047_dP_ACC_200);

	struct max17042_config_data *config = chip->pdata->config_data;

	vfSoc = max17042_read_reg(chip->client, MAX17042_VFSOC);

	/* vfSoc needs to shifted by 8 bits to get the
	 * perc in 1% accuracy, to get the right rem_cap multiply
	 * fullcapnom by vfSoc and devide by 100
	 */
	rem_cap = ((vfSoc >> 8) * config->fullcapnom) / 100;
	max17042_write_verify_reg(chip->client, MAX17042_RemCap, (u16)rem_cap);

	rep_cap = (u16)rem_cap;
	max17042_write_verify_reg(chip->client, MAX17042_RepCap, rep_cap);

	/* Write dQ_acc to 200% of Capacity and dP_acc to 200% */
	dq_acc = config->fullcap / dQ_ACC_DIV;
	max17042_write_verify_reg(chip->client, MAX17042_dQacc, dq_acc);
	max17042_write_verify_reg(chip->client, MAX17042_dPacc, dP_ACC_200);

	max17042_write_verify_reg(chip->client, MAX17042_FullCAP,
			config->fullcap);
	max17042_write_reg(chip->client, MAX17042_DesignCap,
			config->design_cap);
	max17042_write_verify_reg(chip->client, MAX17042_FullCAPNom,
			config->fullcapnom);
	/* Update SOC register with new SOC */
	max17042_write_reg(chip->client, MAX17042_RepSOC, vfSoc);
}

/*
 * Block write all the override values coming from platform data.
 * This function MUST be called before the POR initialization proceedure
 * specified by maxim.
 */
static inline void max17042_override_por_values(struct max17042_chip *chip)
{
	struct i2c_client *client = chip->client;
	struct max17042_config_data *config = chip->pdata->config_data;

	max17042_override_por(client, MAX17042_TGAIN, config->tgain);
	max17042_override_por(client, MAx17042_TOFF, config->toff);
	max17042_override_por(client, MAX17042_CGAIN, config->cgain);
	max17042_override_por(client, MAX17042_COFF, config->coff);

	max17042_override_por(client, MAX17042_VALRT_Th, config->valrt_thresh);
	max17042_override_por(client, MAX17042_TALRT_Th, config->talrt_thresh);
	max17042_override_por(client, MAX17042_SALRT_Th,
			config->soc_alrt_thresh);
	max17042_override_por(client, MAX17042_CONFIG, config->config);
	max17042_override_por(client, MAX17042_SHDNTIMER, config->shdntimer);

	max17042_override_por(client, MAX17042_DesignCap, config->design_cap);
	max17042_override_por(client, MAX17042_ICHGTerm, config->ichgt_term);

	max17042_override_por(client, MAX17042_AtRate, config->at_rate);
	max17042_override_por(client, MAX17042_LearnCFG, config->learn_cfg);
	max17042_override_por(client, MAX17042_FilterCFG, config->filter_cfg);
	max17042_override_por(client, MAX17042_RelaxCFG, config->relax_cfg);
	max17042_override_por(client, MAX17042_MiscCFG, config->misc_cfg);
	max17042_override_por(client, MAX17042_MaskSOC, config->masksoc);

	max17042_override_por(client, MAX17042_FullCAP, config->fullcap);
	max17042_override_por(client, MAX17042_FullCAPNom, config->fullcapnom);
	if (chip->chip_type == MAX17042)
		max17042_override_por(client, MAX17042_SOC_empty,
						config->socempty);
	max17042_override_por(client, MAX17042_LAvg_empty, config->lavg_empty);
	max17042_override_por(client, MAX17042_dQacc, config->dqacc);
	max17042_override_por(client, MAX17042_dPacc, config->dpacc);

	if (chip->chip_type == MAX17042)
		max17042_override_por(client, MAX17042_V_empty, config->vempty);
	else
		max17042_override_por(client, MAX17047_V_empty, config->vempty);
	max17042_override_por(client, MAX17042_TempNom, config->temp_nom);
	max17042_override_por(client, MAX17042_TempLim, config->temp_lim);
	max17042_override_por(client, MAX17042_FCTC, config->fctc);
	max17042_override_por(client, MAX17042_RCOMP0, config->rcomp0);
	max17042_override_por(client, MAX17042_TempCo, config->tcompc0);
	if (chip->chip_type == MAX17042) {
		max17042_override_por(client, MAX17042_EmptyTempCo,
					config->empty_tempco);
		max17042_override_por(client, MAX17042_K_empty0,
					config->kempty0);
	}
}

static int max17042_init_chip(struct max17042_chip *chip)
{
	int ret;
	int val;

	max17042_override_por_values(chip);
	/* After Power up, the MAX17042 requires 500mS in order
	 * to perform signal debouncing and initial SOC reporting
	 */
	msleep(500);

	/* Initialize configaration */
	max17042_write_config_regs(chip);

	/* write cell characterization data */
	ret = max17042_init_model(chip);
	if (ret) {
		dev_err(&chip->client->dev, "%s init failed\n",
			__func__);
		return -EIO;
	}

	ret = max17042_verify_model_lock(chip);
	if (ret) {
		dev_err(&chip->client->dev, "%s lock verify failed\n",
			__func__);
		return -EIO;
	}
	/* write custom parameters */
	max17042_write_custom_regs(chip);

	/* update capacity params */
	max17042_update_capacity_regs(chip);

	/* delay must be atleast 350mS to allow VFSOC
	 * to be calculated from the new configuration
	 */
	msleep(350);

	/* reset vfsoc0 reg */
	max17042_reset_vfsoc0_reg(chip);

	/* advance to coulomb-counter mode */
	max17042_advance_to_coulomb_counter_mode(chip);

	/* load new capacity params */
	max17042_load_new_capacity_params(chip);

	/* Init complete, Clear the POR bit */
	val = max17042_read_reg(chip->client, MAX17042_STATUS);
	max17042_write_reg(chip->client, MAX17042_STATUS,
			val & (~STATUS_POR_BIT));
	return 0;
}

static void max17042_set_soc_threshold(struct max17042_chip *chip, u16 off)
{
	u16 soc, soc_tr;
	/*
	 * Program interrupt thresholds to get interrupt for every 'off'
	 * percent change in the soc. Since we truncate soc value when
	 * reporting it, the reported SOC is equal to (min Salrt - 1) when soc
	 * falls below the min Salrt threshold and equal to max Salrt when soc
	 * exceeds the max Salrt threshold.
	 */
	u16 off_max = off;
	u16 off_min = off - 1;

	soc = max17042_read_reg(chip->client, MAX17042_RepSOC) >> 8;
	soc_tr = (soc + off_max) << 8;
	if (soc >= off_min)
		soc_tr |= (soc - off_min);
	max17042_write_reg(chip->client, MAX17042_SALRT_Th, soc_tr);
}

static irqreturn_t max17042_thread_handler(int id, void *dev)
{
	struct max17042_chip *chip = dev;
	u16 val;

	val = max17042_read_reg(chip->client, MAX17042_STATUS);

	dev_dbg(&chip->client->dev, "status:0x%x soc_tr:0x%x\n",
		 val, chip->alert_threshold);

	if ((val & STATUS_SMN_BIT) || (val & STATUS_SMX_BIT)) {
		max17042_set_soc_threshold(chip, chip->alert_threshold);
		/* clear the  Smin Smax bits if set */
		if (chip->pdata->config_data->config & CONFIG_SS_BIT_ENBL)
			val &= ~STATUS_SMN_BIT & ~STATUS_SMX_BIT;
	}

	/* if sticky bits are used, clear them */
	if (chip->pdata->config_data->config & CONFIG_STICK_ALL_ENBL)
		max17042_write_reg(chip->client, MAX17042_STATUS, val);

	power_supply_changed(&chip->battery);
	return IRQ_HANDLED;
}

static void max17042_init_worker(struct work_struct *work)
{
	struct max17042_chip *chip = container_of(work,
				struct max17042_chip, work);
	int ret;

	/* Initialize registers according to values from the platform data */
	if (chip->pdata->enable_por_init && chip->pdata->config_data) {
		ret = max17042_init_chip(chip);
		if (ret)
			return;
	}

	chip->init_complete = 1;
	if (chip->chip_type == MAX17047)
		max17042_write_reg(chip->client, MAX17047_Config_Ver,
					chip->pdata->config_data->version);
}

#ifdef CONFIG_OF
static  struct gpio *
max17042_get_gpio_list(struct device *dev, int *num_gpio_list)
{
	struct device_node *np = dev->of_node;
	struct gpio *gpio_list;
	int i, num_gpios, gpio_list_size;
	enum of_gpio_flags flags;

	if (!np)
		return NULL;

	num_gpios = of_gpio_count(np);
	if (num_gpios <= 0)
		return NULL;

	gpio_list_size = sizeof(struct gpio) * num_gpios;
	gpio_list = devm_kzalloc(dev, gpio_list_size, GFP_KERNEL);

	if (!gpio_list)
		return NULL;

	*num_gpio_list = num_gpios;
	for (i = 0; i < num_gpios; i++) {
		gpio_list[i].gpio = of_get_gpio_flags(np, i, &flags);
		gpio_list[i].flags = flags;
		of_property_read_string_index(np, "gpio-names", i,
					      &gpio_list[i].label);
	}

	return gpio_list;
}

static struct max17042_reg_data *
max17042_get_init_data(struct device *dev, int *num_init_data)
{
	struct device_node *np = dev->of_node;
	const __be32 *property;
	static struct max17042_reg_data *init_data;
	int i, lenp, num_cells, init_data_size;

	if (!np)
		return NULL;

	property = of_get_property(np, INIT_DATA_PROPERTY, &lenp);

	if (!property || lenp <= 0)
		return NULL;

	/*
	 * Check data validity and whether number of cells is even
	 */
	if (lenp % sizeof(*property)) {
		dev_err(dev, "%s has invalid data\n", INIT_DATA_PROPERTY);
		return NULL;
	}

	num_cells = lenp / sizeof(*property);
	if (num_cells % 2) {
		dev_err(dev, "%s must have even number of cells\n",
			INIT_DATA_PROPERTY);
		return NULL;
	}

	*num_init_data = num_cells / 2;
	init_data_size = sizeof(struct max17042_reg_data) * (num_cells / 2);
	init_data = (struct max17042_reg_data *)
		    devm_kzalloc(dev, init_data_size, GFP_KERNEL);

	if (init_data) {
		for (i = 0; i < num_cells / 2; i++) {
			init_data[i].addr = be32_to_cpu(property[2 * i]);
			init_data[i].data = be32_to_cpu(property[2 * i + 1]);
		}
	}

	return init_data;
}

static int max17042_get_cell_char_tbl(struct device *dev,
				      struct device_node *np,
				      struct max17042_config_data *config_data)
{
	const __be16 *property;
	int i, lenp;

	property = of_get_property(np, CELL_CHAR_TBL_PROPERTY, &lenp);
	if (!property)
		return -ENODEV ;

	if (lenp != sizeof(*property) * MAX17042_CHARACTERIZATION_DATA_SIZE) {
		dev_err(dev, "%s must have %d cells\n", CELL_CHAR_TBL_PROPERTY,
			MAX17042_CHARACTERIZATION_DATA_SIZE);
		return -EINVAL;
	}

	for (i = 0; i < MAX17042_CHARACTERIZATION_DATA_SIZE; i++)
		config_data->cell_char_tbl[i] = be16_to_cpu(property[i]);

	return 0;
}

static int max17042_cfg_rqrd_prop(struct device *dev,
				  struct device_node *np,
				  struct max17042_config_data *config_data)
{
	if (of_property_read_u16(np, VERSION_PROPERTY,
				 &config_data->version))
		return -EINVAL;

	if (of_property_read_u16(np, CONFIG_PROPERTY,
				 &config_data->config))
		return -EINVAL;
	if (of_property_read_u16(np, FILTER_CFG_PROPERTY,
				 &config_data->filter_cfg))
		return -EINVAL;
	if (of_property_read_u16(np, RELAX_CFG_PROPERTY,
				 &config_data->relax_cfg))
		return -EINVAL;
	if (of_property_read_u16(np, LEARN_CFG_PROPERTY,
				 &config_data->learn_cfg))
		return -EINVAL;
	if (of_property_read_u16(np, FULL_SOC_THRESH_PROPERTY,
				 &config_data->full_soc_thresh))
		return -EINVAL;
	if (of_property_read_u16(np, RCOMP0_PROPERTY,
				 &config_data->rcomp0))
		return -EINVAL;
	if (of_property_read_u16(np, TCOMPC0_PROPERTY,
				 &config_data->tcompc0))
		return -EINVAL;
	if (of_property_read_u16(np, ICHGT_TERM_PROPERTY,
				 &config_data->ichgt_term))
		return -EINVAL;
	if (of_property_read_u16(np, QRTBL00_PROPERTY,
				 &config_data->qrtbl00))
		return -EINVAL;
	if (of_property_read_u16(np, QRTBL10_PROPERTY,
				 &config_data->qrtbl10))
		return -EINVAL;
	if (of_property_read_u16(np, QRTBL20_PROPERTY,
				 &config_data->qrtbl20))
		return -EINVAL;
	if (of_property_read_u16(np, QRTBL30_PROPERTY,
				 &config_data->qrtbl30))
		return -EINVAL;
	if (of_property_read_u16(np, FULLCAP_PROPERTY,
				 &config_data->fullcap))
		return -EINVAL;
	if (of_property_read_u16(np, DESIGN_CAP_PROPERTY,
				 &config_data->design_cap))
		return -EINVAL;
	if (of_property_read_u16(np, FULLCAPNOM_PROPERTY,
				 &config_data->fullcapnom))
		return -EINVAL;

	return max17042_get_cell_char_tbl(dev, np, config_data);
}

static void max17042_cfg_optnl_prop(struct device_node *np,
				    struct max17042_config_data *config_data)
{
	of_property_read_u16(np, TGAIN_PROPERTY, &config_data->tgain);
	of_property_read_u16(np, TOFF_PROPERTY, &config_data->toff);
}

static struct max17042_config_data *
max17042_get_config_data(struct device *dev)
{
	char *config_node = NULL;
	char config_node_path[64];
	struct max17042_config_data *config_data;
	struct device_node *np = NULL;

	if (!dev->of_node)
		return NULL;

	config_node = (char *)get_dts_batt_id(dev);
	if (config_node) {
		dev_info(dev, "using %s profile\n", config_node);
		snprintf(config_node_path, sizeof(config_node_path),
			 "%s-%s", CONFIG_NODE, config_node);
		np = of_get_child_by_name(dev->of_node, config_node_path);
	}

	if (!np) {
		dev_info(dev, "using %s profile\n", CONFIG_NODE);
		np = of_get_child_by_name(dev->of_node, CONFIG_NODE);
		if (!np)
			return NULL;
	}

	config_data = devm_kzalloc(dev, sizeof(*config_data), GFP_KERNEL);
	if (!config_data)
		return NULL;

	if (max17042_cfg_rqrd_prop(dev, np, config_data)) {
		devm_kfree(dev, config_data);
		return NULL;
	}

	max17042_cfg_optnl_prop(np, config_data);

	return config_data;
}

static struct max17042_temp_conv *
max17042_get_conv_table(struct device *dev)
{
	struct device_node *np = dev->of_node;
	struct max17042_temp_conv *temp_conv;
	const __be16 *property;
	int i, lenp, num;
	u16 temp;
	s16 start;

	if (!np)
		return NULL;

	np = of_get_child_by_name(np, TEMP_CONV_NODE);
	if (!np)
		return NULL;

	property = of_get_property(np, RESULT_PROPERTY, &lenp);
	if (!property || lenp <= 0) {
		dev_err(dev, "%s must have %s property\n", TEMP_CONV_NODE,
			RESULT_PROPERTY);
		return NULL;
	}

	if (of_property_read_u16(np, START_PROPERTY, &temp)) {
		dev_err(dev, "%s must have %s property\n", TEMP_CONV_NODE,
			START_PROPERTY);
		return NULL;
	}

	start = (s16) temp;

	temp_conv = devm_kzalloc(dev, sizeof(*temp_conv), GFP_KERNEL);
	if (!temp_conv)
		return NULL;

	num = lenp / sizeof(*property);
	temp_conv->result = devm_kzalloc(dev, sizeof(s16) * num, GFP_KERNEL);
	if (!temp_conv->result) {
		devm_kfree(dev, temp_conv);
		return NULL;
	}

	temp_conv->start = start;
	temp_conv->num_result = num;

	for (i = 0; i < num; i++) {
		temp = be16_to_cpu(property[i]);
		temp_conv->result[i] = (s16) temp;
	}

	return temp_conv;
}


static struct max17042_platform_data *
max17042_get_pdata(struct device *dev)
{
	struct device_node *np = dev->of_node;
	u32 prop;
	struct max17042_platform_data *pdata;

	if (!np)
		return dev->platform_data;

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata)
		return NULL;

	pdata->init_data = max17042_get_init_data(dev, &pdata->num_init_data);
	pdata->gpio_list = max17042_get_gpio_list(dev, &pdata->num_gpio_list);

	/*
	 * Require current sense resistor value to be specified for
	 * current-sense functionality to be enabled at all.
	 */
	if (of_property_read_u32(np, "maxim,rsns-microohm", &prop) == 0) {
		pdata->r_sns = prop;
		pdata->enable_current_sense = true;
	}

	pdata->enable_por_init =
		of_property_read_bool(np, "maxim,enable_por_init");

	pdata->config_data = max17042_get_config_data(dev);
	if (!pdata->config_data)
		dev_warn(dev, "config data is missing\n");

	pdata->tcnv = max17042_get_conv_table(dev);

	return pdata;
}
#else
static struct max17042_platform_data *
max17042_get_pdata(struct device *dev)
{
	return dev->platform_data;
}
#endif

#ifdef CONFIG_BATTERY_MAX17042_DEBUGFS
static int max17042_debugfs_read_addr(void *data, u64 *val)
{
	struct max17042_chip *chip = (struct max17042_chip *)data;
	*val = chip->debugfs_addr;
	return 0;
}

static int max17042_debugfs_write_addr(void *data, u64 val)
{
	struct max17042_chip *chip = (struct max17042_chip *)data;
	chip->debugfs_addr = val;
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(addr_fops, max17042_debugfs_read_addr,
			max17042_debugfs_write_addr, "0x%02llx\n");

static int max17042_debugfs_read_data(void *data, u64 *val)
{
	struct max17042_chip *chip = (struct max17042_chip *)data;
	int ret = max17042_read_reg(chip->client, chip->debugfs_addr);

	if (ret < 0)
		return ret;

	*val = ret;
	return 0;
}

static int max17042_debugfs_write_data(void *data, u64 val)
{
	struct max17042_chip *chip = (struct max17042_chip *)data;
	return max17042_write_reg(chip->client, chip->debugfs_addr, val);
}
DEFINE_SIMPLE_ATTRIBUTE(data_fops, max17042_debugfs_read_data,
			max17042_debugfs_write_data, "0x%02llx\n");

static int max17042_debugfs_read_capacity(void *data, u64 *val)
{
	struct max17042_chip *chip = (struct max17042_chip *)data;
	*val = chip->debugfs_capacity;
	return 0;
}

static int max17042_debugfs_write_capacity(void *data, u64 val)
{
	struct max17042_chip *chip = (struct max17042_chip *)data;
	chip->debugfs_capacity = val;
	power_supply_changed(&chip->battery);
	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(capacity_fops, max17042_debugfs_read_capacity,
			max17042_debugfs_write_capacity, "%llu\n");

static int max17042_debugfs_create(struct max17042_chip *chip)
{
	chip->debugfs_root = debugfs_create_dir(dev_name(&chip->client->dev),
						NULL);
	if (!chip->debugfs_root)
		return -ENOMEM;

	if (!debugfs_create_file("addr", S_IRUGO | S_IWUSR, chip->debugfs_root,
				 chip, &addr_fops))
		goto err_debugfs;

	if (!debugfs_create_file("data", S_IRUGO | S_IWUSR, chip->debugfs_root,
				 chip, &data_fops))
		goto err_debugfs;

	chip->debugfs_capacity = 0xFF;
	if (!debugfs_create_file("capacity", S_IRUGO | S_IWUSR,
				 chip->debugfs_root, chip, &capacity_fops))
		goto err_debugfs;

	return 0;

err_debugfs:
	debugfs_remove_recursive(chip->debugfs_root);
	chip->debugfs_root = NULL;
	return -ENOMEM;
}
#endif

static ssize_t max17042_show_alert_threshold(struct device *dev,
		struct device_attribute *attr,
		char *buf)
{
	struct max17042_chip *chip = dev_get_drvdata(dev);

	return snprintf(buf, PAGE_SIZE, "%u\n", chip->alert_threshold);
}

static ssize_t max17042_store_alert_threshold(struct device *dev,
		struct device_attribute *attr,
		const char *buf, size_t count)
{
	struct max17042_chip *chip = dev_get_drvdata(dev);
	unsigned long t;
	u16 r;

	r = kstrtoul(buf, 10, &t);
	if ((!r) && ( r < 100 )) {
		chip->alert_threshold = (u16)t;
		max17042_set_soc_threshold(chip, chip->alert_threshold);
	}

	return r ? r : count;
}

static DEVICE_ATTR(alert_threshold, S_IRUGO | S_IWUSR,
		max17042_show_alert_threshold, max17042_store_alert_threshold);


static ssize_t max17042_show_battery_age(struct device *dev,
					 struct device_attribute *attr,
					 char *buf)
{
	struct max17042_chip *chip = dev_get_drvdata(dev);
	int ret = max17042_read_reg(chip->client, MAX17042_Age);

	return ret < 0 ? ret : sprintf(buf, "%u\n", ret / MAX17042_AGE_DIV);
}
static DEVICE_ATTR(battery_age, S_IRUGO, max17042_show_battery_age, NULL);

static struct attribute *max17042_attrs[] = {
	&dev_attr_alert_threshold.attr,
	&dev_attr_battery_age.attr,
	NULL,
};

static struct attribute_group max17042_attr_group = {
	.attrs = max17042_attrs,
};

static bool max17042_new_config_data(struct max17042_chip *chip)
{
	int ret;

	if (chip->chip_type != MAX17047)
		return false;

	ret = max17042_read_reg(chip->client, MAX17047_Config_Ver);
	if (ret < 0)
		return false;

	return (chip->pdata->config_data->version != ret);
}

static int max17042_probe(struct i2c_client *client,
			const struct i2c_device_id *id)
{
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct max17042_chip *chip;
	int ret;
	int reg;

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_WORD_DATA))
		return -EIO;

	chip = devm_kzalloc(&client->dev, sizeof(*chip), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;

	chip->client = client;
	chip->pdata = max17042_get_pdata(&client->dev);
	if (!chip->pdata) {
		dev_err(&client->dev, "no platform data provided\n");
		return -EINVAL;
	}

	i2c_set_clientdata(client, chip);

	ret = max17042_read_reg(chip->client, MAX17042_DevName);
	if (ret == MAX17042_IC_VERSION) {
		dev_dbg(&client->dev, "chip type max17042 detected\n");
		chip->chip_type = MAX17042;
	} else if (ret == MAX17047_IC_VERSION) {
		dev_dbg(&client->dev, "chip type max17047/50 detected\n");
		chip->chip_type = MAX17047;
	} else {
		dev_err(&client->dev, "device version mismatch: %x\n", ret);
		return -EIO;
	}

	chip->battery.name		= "max170xx_battery";
	chip->battery.type		= POWER_SUPPLY_TYPE_BATTERY;
	chip->battery.get_property	= max17042_get_property;
	chip->battery.properties	= max17042_battery_props;
	chip->battery.num_properties	= ARRAY_SIZE(max17042_battery_props);

	chip->alert_threshold = DEFAULT_ALERT_THRESHOLD;

	/* When current is not measured,
	 * CURRENT_NOW and CURRENT_AVG properties should be invisible. */
	if (!chip->pdata->enable_current_sense)
		chip->battery.num_properties -= 2;

	if (chip->pdata->r_sns == 0)
		chip->pdata->r_sns = MAX17042_DEFAULT_SNS_RESISTOR;

	if (chip->pdata->init_data)
		max17042_set_reg(client, chip->pdata->init_data,
				chip->pdata->num_init_data);

	if (!chip->pdata->enable_current_sense) {
		max17042_write_reg(client, MAX17042_CGAIN, 0x0000);
		max17042_write_reg(client, MAX17042_MiscCFG, 0x0003);
		max17042_write_reg(client, MAX17042_LearnCFG, 0x0007);
	}

	ret = power_supply_register(&client->dev, &chip->battery);
	if (ret) {
		dev_err(&client->dev, "failed: power supply register\n");
		return ret;
	}

	ret = gpio_request_array(chip->pdata->gpio_list,
				 chip->pdata->num_gpio_list);
	if (ret) {
		dev_err(&client->dev, "cannot request GPIOs\n");
		return ret;
	}

	if (client->irq) {
		/* Disable and clear SOC alerts until irq is requested */
		max17042_write_reg(client, MAX17042_SALRT_Th, 0xFF00);
		reg = max17042_read_reg(client, MAX17042_STATUS);
		reg &= ~(STATUS_SMN_BIT | STATUS_SMX_BIT);
		max17042_write_reg(client, MAX17042_STATUS, reg);

		ret = request_threaded_irq(client->irq, NULL,
						max17042_thread_handler,
						IRQF_TRIGGER_FALLING |
						IRQF_ONESHOT,
						chip->battery.name, chip);
		if (!ret) {
			reg =  max17042_read_reg(client, MAX17042_CONFIG);
			reg |= CONFIG_ALRT_BIT_ENBL;
			max17042_write_reg(client, MAX17042_CONFIG, reg);
			max17042_set_soc_threshold(chip, chip->alert_threshold);
		} else {
			client->irq = 0;
			dev_err(&client->dev, "%s(): cannot get IRQ\n",
				__func__);
		}
	}

	reg = max17042_read_reg(chip->client, MAX17042_STATUS);
	if (reg & STATUS_POR_BIT || max17042_new_config_data(chip)) {
		INIT_WORK(&chip->work, max17042_init_worker);
		schedule_work(&chip->work);
	} else {
		chip->init_complete = 1;
	}

#ifdef CONFIG_BATTERY_MAX17042_DEBUGFS
	ret = max17042_debugfs_create(chip);
	if (ret) {
		dev_err(&client->dev, "cannot create debugfs\n");
		return ret;
	}
#endif

	ret = sysfs_create_group(&client->dev.kobj, &max17042_attr_group);
	if (ret)
		dev_err(&client->dev, "failed to create sysfs files\n");

	return 0;
}

static int max17042_remove(struct i2c_client *client)
{
	struct max17042_chip *chip = i2c_get_clientdata(client);

#ifdef CONFIG_BATTERY_MAX17042_DEBUGFS
	debugfs_remove_recursive(chip->debugfs_root);
#endif

	sysfs_remove_group(&client->dev.kobj, &max17042_attr_group);

	if (client->irq)
		free_irq(client->irq, chip);
	gpio_free_array(chip->pdata->gpio_list, chip->pdata->num_gpio_list);
	power_supply_unregister(&chip->battery);
	return 0;
}

#ifdef CONFIG_PM
static int max17042_suspend(struct device *dev)
{
	struct max17042_chip *chip = dev_get_drvdata(dev);

	/*
	 * disable the irq and enable irq_wake
	 * capability to the interrupt line.
	 */
	if (chip->client->irq) {
		disable_irq(chip->client->irq);
		enable_irq_wake(chip->client->irq);
	}

	return 0;
}

static int max17042_resume(struct device *dev)
{
	struct max17042_chip *chip = dev_get_drvdata(dev);

	if (chip->client->irq) {
		disable_irq_wake(chip->client->irq);
		enable_irq(chip->client->irq);
		/* re-program the SOC thresholds to 1% change */
		max17042_set_soc_threshold(chip, chip->alert_threshold);
	}

	return 0;
}

static const struct dev_pm_ops max17042_pm_ops = {
	.suspend	= max17042_suspend,
	.resume		= max17042_resume,
};

#define MAX17042_PM_OPS (&max17042_pm_ops)
#else
#define MAX17042_PM_OPS NULL
#endif

#ifdef CONFIG_OF
static const struct of_device_id max17042_dt_match[] = {
	{ .compatible = "maxim,max17042" },
	{ .compatible = "maxim,max17047" },
	{ .compatible = "maxim,max17050" },
	{ },
};
MODULE_DEVICE_TABLE(of, max17042_dt_match);
#endif

static const struct i2c_device_id max17042_id[] = {
	{ "max17042", 0 },
	{ "max17047", 1 },
	{ "max17050", 2 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, max17042_id);

static struct i2c_driver max17042_i2c_driver = {
	.driver	= {
		.name	= "max17042",
		.of_match_table = of_match_ptr(max17042_dt_match),
		.pm	= MAX17042_PM_OPS,
	},
	.probe		= max17042_probe,
	.remove		= max17042_remove,
	.id_table	= max17042_id,
};
module_i2c_driver(max17042_i2c_driver);

MODULE_AUTHOR("MyungJoo Ham <myungjoo.ham@samsung.com>");
MODULE_DESCRIPTION("MAX17042 Fuel Gauge");
MODULE_LICENSE("GPL");
