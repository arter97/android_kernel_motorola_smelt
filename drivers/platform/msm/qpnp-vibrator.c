/* Copyright (c) 2013-2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/spmi.h>
#include <linux/qpnp/pwm.h>
#include <linux/err.h>
#include "../../staging/android/timed_output.h"

#define QPNP_VIB_VTG_CTL(base)		(base + 0x41)
#define QPNP_VIB_EN_CTL(base)		(base + 0x46)

#define QPNP_VIB_MAX_LEVEL		31
#define QPNP_VIB_MIN_LEVEL		12

#define QPNP_VIB_DEFAULT_TIMEOUT	15000
#define QPNP_VIB_DEFAULT_VTG_LVL	3100

#define QPNP_VIB_EN			BIT(7)
#define QPNP_VIB_VTG_SET_MASK		0x1F
#define QPNP_VIB_LOGIC_SHIFT		4

enum qpnp_vib_mode {
	QPNP_VIB_MANUAL,
	QPNP_VIB_DTEST1,
	QPNP_VIB_DTEST2,
	QPNP_VIB_DTEST3,
};

struct qpnp_pwm_info {
	struct pwm_device *pwm_dev;
	u32 pwm_channel;
	u32 duty_us;
	u32 period_us;
};

struct qpnp_vib {
	struct spmi_device *spmi;
	struct timed_output_dev timed_dev;
	struct delayed_work turnoff_work;
	struct work_struct custom_work;
	struct qpnp_pwm_info pwm_info;
	enum   qpnp_vib_mode mode;

	u8  reg_vtg_ctl;
	u8  reg_en_ctl;
	u8  active_low;
	u16 base;
	int state;
	int vtg_level;
	int wanted_vtg_level;
	int prev_vtg_level;
	int timeout;
	int cur;
	struct mutex lock;
};

static void qpnp_vib_turnoff(struct qpnp_vib *vib, int check);

static int qpnp_vib_read_u8(struct qpnp_vib *vib, u8 *data, u16 reg)
{
	int rc;

	rc = spmi_ext_register_readl(vib->spmi->ctrl, vib->spmi->sid,
							reg, data, 1);
	if (rc < 0)
		dev_err(&vib->spmi->dev,
			"Error reading address: %X - ret %X\n", reg, rc);

	return rc;
}

static int qpnp_vib_write_u8(struct qpnp_vib *vib, u8 *data, u16 reg)
{
	int rc;

	rc = spmi_ext_register_writel(vib->spmi->ctrl, vib->spmi->sid,
							reg, data, 1);
	if (rc < 0)
		dev_err(&vib->spmi->dev,
			"Error writing address: %X - ret %X\n", reg, rc);

	return rc;
}

static int qpnp_vibrator_config(struct qpnp_vib *vib)
{
	u8 reg = 0;
	int rc;

	/* Configure the VTG CTL regiser */
	rc = qpnp_vib_read_u8(vib, &reg, QPNP_VIB_VTG_CTL(vib->base));
	if (rc < 0)
		return rc;
	reg &= ~QPNP_VIB_VTG_SET_MASK;
	reg |= (vib->vtg_level & QPNP_VIB_VTG_SET_MASK);
	rc = qpnp_vib_write_u8(vib, &reg, QPNP_VIB_VTG_CTL(vib->base));
	if (rc)
		return rc;
	vib->reg_vtg_ctl = reg;

	/* Configure the VIB ENABLE regiser */
	rc = qpnp_vib_read_u8(vib, &reg, QPNP_VIB_EN_CTL(vib->base));
	if (rc < 0)
		return rc;
	reg |= (!!vib->active_low) << QPNP_VIB_LOGIC_SHIFT;
	if (vib->mode != QPNP_VIB_MANUAL) {
		vib->pwm_info.pwm_dev = pwm_request(vib->pwm_info.pwm_channel,
								 "qpnp-vib");
		if (IS_ERR_OR_NULL(vib->pwm_info.pwm_dev)) {
			dev_err(&vib->spmi->dev, "vib pwm request failed\n");
			return -ENODEV;
		}

		rc = pwm_config(vib->pwm_info.pwm_dev, vib->pwm_info.duty_us,
						vib->pwm_info.period_us);
		if (rc < 0) {
			dev_err(&vib->spmi->dev, "vib pwm config failed\n");
			pwm_free(vib->pwm_info.pwm_dev);
			return -ENODEV;
		}

		reg |= BIT(vib->mode - 1);
	}

	rc = qpnp_vib_write_u8(vib, &reg, QPNP_VIB_EN_CTL(vib->base));
	if (rc < 0)
		return rc;
	vib->reg_en_ctl = reg;

	return rc;
}

static int qpnp_set_vtg_level(struct qpnp_vib *vib, int val)
{
	int rc;
	u8 reg = 0;

	if (val < QPNP_VIB_MIN_LEVEL) {
		pr_err("%s: level %d not in range (%d - %d), using min.", __func__, val, QPNP_VIB_MIN_LEVEL, QPNP_VIB_MAX_LEVEL);
		val = QPNP_VIB_MIN_LEVEL;
	} else if (val > QPNP_VIB_MAX_LEVEL) {
		pr_err("%s: level %d not in range (%d - %d), using max.", __func__, val, QPNP_VIB_MIN_LEVEL, QPNP_VIB_MAX_LEVEL);
		val = QPNP_VIB_MAX_LEVEL;
	}

	vib->vtg_level = val;

	/* Configure the VTG CTL regiser */
	rc = qpnp_vib_read_u8(vib, &reg, QPNP_VIB_VTG_CTL(vib->base));
	if (rc < 0) {
		pr_info("qpnp: error while reading vibration control register\n");
		}
	reg &= ~QPNP_VIB_VTG_SET_MASK;
	reg |= (vib->vtg_level & QPNP_VIB_VTG_SET_MASK);
	rc = qpnp_vib_write_u8(vib, &reg, QPNP_VIB_VTG_CTL(vib->base));
	if (rc)
		pr_info("qpnp: error while writing vibration control register\n");

	return rc;
}

static int qpnp_vib_set(struct qpnp_vib *vib, int on)
{
	int rc;
	u8 val;

	if (on) {
		// Update the VTG level, if necessary
		if (vib->vtg_level != vib->wanted_vtg_level)
			qpnp_set_vtg_level(vib, vib->wanted_vtg_level);

		if (vib->mode != QPNP_VIB_MANUAL)
			pwm_enable(vib->pwm_info.pwm_dev);
		else {
			val = vib->reg_en_ctl;
			val |= QPNP_VIB_EN;
			rc = qpnp_vib_write_u8(vib, &val,
					QPNP_VIB_EN_CTL(vib->base));
			if (rc < 0)
				return rc;
			vib->reg_en_ctl = val;
		}
	} else {
		if (vib->mode != QPNP_VIB_MANUAL)
			pwm_disable(vib->pwm_info.pwm_dev);
		else {
			val = vib->reg_en_ctl;
			val &= ~QPNP_VIB_EN;
			rc = qpnp_vib_write_u8(vib, &val,
					QPNP_VIB_EN_CTL(vib->base));
			if (rc < 0)
				return rc;
			vib->reg_en_ctl = val;
		}
	}

	return 0;
}

// Boost [boost_min,boost_max]ms to use vtg_level of boost_to
static int __read_mostly boost_min = 100;
static int __read_mostly boost_max = 500;
static int __read_mostly boost_to = 28;

module_param(boost_min, int, 0644);
module_param(boost_max, int, 0644);
module_param(boost_to, int, 0644);

static int custom_target = 150;
static int custom_pattern[10] = { 150,50,350,50,0,0,0,0,0,0 };
module_param(custom_target, int, 0644);
module_param_array(custom_pattern, int, NULL, 0644);

static void qpnp_async_play_custom_pattern(struct work_struct *work)
{
	struct qpnp_vib *vib = container_of(work, struct qpnp_vib,
					 custom_work);
	int idx, value;

	for (idx = 0; idx < ARRAY_SIZE(custom_pattern); idx++) {
		value = custom_pattern[idx];
		if (value == 0)
			break;

		if (idx % 2 == 0) {
			// On
			if (boost_min <= value && value <= boost_max) {
				if (vib->wanted_vtg_level != boost_to) {
					vib->prev_vtg_level = vib->wanted_vtg_level;
					vib->wanted_vtg_level = boost_to;
				}
			} else {
				vib->wanted_vtg_level = vib->prev_vtg_level;
			}

			vib->state = 1;
			qpnp_vib_set(vib, vib->state);
			vib->cur = value;
		} else {
			// Off
			vib->state = 0;
			qpnp_vib_set(vib, vib->state);
			vib->cur = 0;
		}
		msleep(value);
	}

	qpnp_vib_turnoff(vib, 1);
}

static void qpnp_vib_enable(struct timed_output_dev *dev, int value)
{
	struct qpnp_vib *vib = container_of(dev, struct qpnp_vib,
					 timed_dev);

	mutex_lock(&vib->lock);
	cancel_work_sync(&vib->custom_work);
	cancel_delayed_work_sync(&vib->turnoff_work);

	if (value == 0) {
		qpnp_vib_turnoff(vib, 0);
	} else {
		value = (value > vib->timeout ?
				 vib->timeout : value);

		if (value && value == custom_target) {
			queue_work(system_highpri_wq, &vib->custom_work);
		} else {
			if (boost_min <= value && value <= boost_max && vib->wanted_vtg_level != boost_to) {
				vib->prev_vtg_level = vib->wanted_vtg_level;
				vib->wanted_vtg_level = boost_to;
			}

			vib->state = 1;
			qpnp_vib_set(vib, vib->state);
			vib->cur = value;
			queue_delayed_work(system_highpri_wq, &vib->turnoff_work, msecs_to_jiffies(value));
		}
	}
	mutex_unlock(&vib->lock);
}

static void qpnp_vib_turnoff(struct qpnp_vib *vib, int check)
{
	if (!check || vib->state == 1) {
		vib->state = 0;
		qpnp_vib_set(vib, vib->state);
		vib->cur = 0;
	}

	// Restore un-boosted vtg_level
	vib->wanted_vtg_level = vib->prev_vtg_level;
}

static void qpnp_vib_turnoff_work(struct work_struct *work)
{
	struct qpnp_vib *vib = container_of(work, struct qpnp_vib, turnoff_work.work);
	qpnp_vib_turnoff(vib, 0);
}

static int qpnp_vib_get_time(struct timed_output_dev *dev)
{
	struct qpnp_vib *vib = container_of(dev, struct qpnp_vib,
							 timed_dev);
	return vib->cur;
}

#ifdef CONFIG_PM
static int qpnp_vibrator_suspend(struct device *dev)
{
	struct qpnp_vib *vib = dev_get_drvdata(dev);

	cancel_delayed_work_sync(&vib->turnoff_work);
	/* turn-off vibrator */
	qpnp_vib_set(vib, 0);
	vib->cur = 0;

	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(qpnp_vibrator_pm_ops, qpnp_vibrator_suspend, NULL);

static int qpnp_vib_parse_dt(struct qpnp_vib *vib)
{
	struct spmi_device *spmi = vib->spmi;
	int rc;
	const char *mode;
	u32 temp_val;

	vib->timeout = QPNP_VIB_DEFAULT_TIMEOUT;
	rc = of_property_read_u32(spmi->dev.of_node,
			"qcom,vib-timeout-ms", &temp_val);
	if (!rc) {
		vib->timeout = temp_val;
	} else if (rc != -EINVAL) {
		dev_err(&spmi->dev, "Unable to read vib timeout\n");
		return rc;
	}

	vib->vtg_level = QPNP_VIB_DEFAULT_VTG_LVL;
	rc = of_property_read_u32(spmi->dev.of_node,
			"qcom,vib-vtg-level-mV", &temp_val);
	if (!rc) {
		vib->vtg_level = temp_val;
	} else if (rc != -EINVAL) {
		dev_err(&spmi->dev, "Unable to read vtg level\n");
		return rc;
	}

	vib->vtg_level /= 100;
	if (vib->vtg_level < QPNP_VIB_MIN_LEVEL)
		vib->vtg_level = QPNP_VIB_MIN_LEVEL;
	else if (vib->vtg_level > QPNP_VIB_MAX_LEVEL)
		vib->vtg_level = QPNP_VIB_MAX_LEVEL;
	vib->wanted_vtg_level = vib->vtg_level;
	vib->prev_vtg_level = vib->vtg_level;

	vib->mode = QPNP_VIB_MANUAL;
	rc = of_property_read_string(spmi->dev.of_node, "qcom,mode", &mode);
	if (!rc) {
		if (strcmp(mode, "manual") == 0)
			vib->mode = QPNP_VIB_MANUAL;
		else if (strcmp(mode, "dtest1") == 0)
			vib->mode = QPNP_VIB_DTEST1;
		else if (strcmp(mode, "dtest2") == 0)
			vib->mode = QPNP_VIB_DTEST2;
		else if (strcmp(mode, "dtest3") == 0)
			vib->mode = QPNP_VIB_DTEST3;
		else {
			dev_err(&spmi->dev, "Invalid mode\n");
			return -EINVAL;
		}
	} else if (rc != -EINVAL) {
		dev_err(&spmi->dev, "Unable to read mode\n");
		return rc;
	}

	if (vib->mode != QPNP_VIB_MANUAL) {
		rc = of_property_read_u32(spmi->dev.of_node,
				"qcom,pwm-channel", &temp_val);
		if (!rc)
			vib->pwm_info.pwm_channel = temp_val;
		else
			return rc;

		rc = of_property_read_u32(spmi->dev.of_node,
				"qcom,period-us", &temp_val);
		if (!rc)
			vib->pwm_info.period_us = temp_val;
		else
			return rc;

		rc = of_property_read_u32(spmi->dev.of_node,
				"qcom,duty-us", &temp_val);
		if (!rc)
			vib->pwm_info.duty_us = temp_val;
		else
			return rc;
	}

	vib->active_low = of_property_read_bool(spmi->dev.of_node,
				"qcom,active-low");

	return 0;
}

static ssize_t qpnp_vib_level_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct timed_output_dev *tdev = dev_get_drvdata(dev);
	struct qpnp_vib *vib = container_of(tdev, struct qpnp_vib,
					 timed_dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n", vib->vtg_level);
}


static ssize_t qpnp_vib_level_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct timed_output_dev *tdev = dev_get_drvdata(dev);
	struct qpnp_vib *vib = container_of(tdev, struct qpnp_vib,
					 timed_dev);
	int val;
	int rc;
	u8 reg = 0;

	rc = kstrtoint(buf, 10, &val);
	if (rc) {
		pr_err("%s: error getting level\n", __func__);
		return -EINVAL;
	}

	qpnp_set_vtg_level(vib, val);
	vib->wanted_vtg_level = val;
	vib->prev_vtg_level = val;

	return strnlen(buf, count);
}
static DEVICE_ATTR(vtg_level, S_IRUGO | S_IWUSR, qpnp_vib_level_show, qpnp_vib_level_store);

static int qpnp_vibrator_probe(struct spmi_device *spmi)
{
	struct qpnp_vib *vib;
	struct resource *vib_resource;
	int rc;

	vib = devm_kzalloc(&spmi->dev, sizeof(*vib), GFP_KERNEL);
	if (!vib)
		return -ENOMEM;

	vib->spmi = spmi;

	vib_resource = spmi_get_resource(spmi, 0, IORESOURCE_MEM, 0);
	if (!vib_resource) {
		dev_err(&spmi->dev, "Unable to get vibrator base address\n");
		return -EINVAL;
	}
	vib->base = vib_resource->start;

	rc = qpnp_vib_parse_dt(vib);
	if (rc) {
		dev_err(&spmi->dev, "DT parsing failed\n");
		return rc;
	}

	rc = qpnp_vibrator_config(vib);
	if (rc) {
		dev_err(&spmi->dev, "vib config failed\n");
		return rc;
	}

	mutex_init(&vib->lock);
	INIT_DELAYED_WORK(&vib->turnoff_work, qpnp_vib_turnoff_work);
	INIT_WORK(&vib->custom_work, qpnp_async_play_custom_pattern);

	vib->timed_dev.name = "vibrator";
	vib->timed_dev.get_time = qpnp_vib_get_time;
	vib->timed_dev.enable = qpnp_vib_enable;

	dev_set_drvdata(&spmi->dev, vib);

	rc = timed_output_dev_register(&vib->timed_dev);
	if (rc < 0)
		return rc;

	device_create_file(vib->timed_dev.dev, &dev_attr_vtg_level);

	return rc;
}

static int qpnp_vibrator_remove(struct spmi_device *spmi)
{
	struct qpnp_vib *vib = dev_get_drvdata(&spmi->dev);

	cancel_delayed_work_sync(&vib->turnoff_work);
	timed_output_dev_unregister(&vib->timed_dev);
	mutex_destroy(&vib->lock);

	return 0;
}

static struct of_device_id spmi_match_table[] = {
	{	.compatible = "qcom,qpnp-vibrator",
	},
	{}
};

static struct spmi_driver qpnp_vibrator_driver = {
	.driver		= {
		.name	= "qcom,qpnp-vibrator",
		.of_match_table = spmi_match_table,
		.pm	= &qpnp_vibrator_pm_ops,
	},
	.probe		= qpnp_vibrator_probe,
	.remove		= qpnp_vibrator_remove,
};

static int __init qpnp_vibrator_init(void)
{
	return spmi_driver_register(&qpnp_vibrator_driver);
}
module_init(qpnp_vibrator_init);

static void __exit qpnp_vibrator_exit(void)
{
	return spmi_driver_unregister(&qpnp_vibrator_driver);
}
module_exit(qpnp_vibrator_exit);

MODULE_DESCRIPTION("qpnp vibrator driver");
MODULE_LICENSE("GPL v2");
