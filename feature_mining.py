#!/usr/bin/python3
"""Module for simulating ipfixprobe for adding new TimeSeries plugin.


author: Josef Koumar
e-mail: koumajos@fit.cvut.cz, koumar@cesnet.cz

Copyright (C) 2022 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above.

This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.
"""
# Standard libraries imports
import sys
import csv

csv.field_size_limit(sys.maxsize)

import time
import argparse
from argparse import RawTextHelpFormatter
import statistics
import math
import numpy as np
import json
from scipy.stats import norm
from statsmodels.stats.diagnostic import lilliefors
from scipy.special import gamma
from astropy.timeseries import LombScargle
from collections import Counter


import warnings

warnings.filterwarnings("ignore")

# 4x speeder than scapy
from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp


DEFAULT_VALUE = "" # 0
DEFAULT_VALUE_DIR = -1


class TimeSeriesPlugin(object):
    def __init__(self,src_ip, dst_ip, src_port, dst_port):
        # Basic plugin features
        self.DST_IP = dst_ip
        self.SRC_IP = src_ip
        self.BYTES = 0
        self.BYTES_REV = 0
        self.TIME_FIRST = 0
        self.TIME_LAST = 0
        self.PACKETS = 0
        self.PACKETS_REV = 0
        self.DST_PORT = dst_port
        self.SRC_PORT = src_port
        # statistics-based features
        self.MEAN = DEFAULT_VALUE
        self.MEDIAN = DEFAULT_VALUE
        self.STDEV = DEFAULT_VALUE
        self.VAR = DEFAULT_VALUE
        self.BURSTINESS = DEFAULT_VALUE
        self.Q1 = DEFAULT_VALUE
        self.Q3 = DEFAULT_VALUE
        self.MIN = DEFAULT_VALUE
        self.MAX = DEFAULT_VALUE
        self.MIN_MINUS_MAX = DEFAULT_VALUE
        self.MODE = DEFAULT_VALUE
        self.COEFFICIENT_OF_VARIATION = DEFAULT_VALUE
        self.AVERAGE_DISPERSION = DEFAULT_VALUE
        self.PERCENT_DEVIATION = DEFAULT_VALUE
        self.ROOT_MEAN_SQUARE = DEFAULT_VALUE
        self.PERCENT_BELOW_MEAN = DEFAULT_VALUE
        self.PERCENT_ABOVE_MEAN = DEFAULT_VALUE
        self.PEARSON_SK1_SKEWNESS = DEFAULT_VALUE
        self.PEARSON_SK2_SKEWNESS = DEFAULT_VALUE
        self.FISHER_MI_3_SKEWNESS = DEFAULT_VALUE
        self.FISHER_PEARSON_g1_SKEWNESS = DEFAULT_VALUE
        self.FISHER_PEARSON_G1_SKEWNESS = DEFAULT_VALUE
        self.GALTON_SKEWNESS = DEFAULT_VALUE
        self.KURTOSIS = DEFAULT_VALUE
        self.ENTROPY = DEFAULT_VALUE
        self.SCALED_ENTROPY = DEFAULT_VALUE
        # distribution-based features
        self.HURST_EXPONENT = DEFAULT_VALUE
        self.BENFORD_LAW_PRESENTED = False
        self.P_BENFORD = DEFAULT_VALUE
        self.NORMAL_DISTRIBUTION = DEFAULT_VALUE
        self.CNT_DISTRIBUTION = DEFAULT_VALUE
        self.TIME_DISTRIBUTION = DEFAULT_VALUE
        self.AREA_VALUES_DISTRIBUTION = DEFAULT_VALUE
        # time-based features
        self.MEAN_SCALED_TIME = DEFAULT_VALUE
        self.MEDIAN_SCALED_TIME = DEFAULT_VALUE
        self.Q1_SCALED_TIME = DEFAULT_VALUE
        self.Q3_SCALED_TIME = DEFAULT_VALUE
        self.DURATION = DEFAULT_VALUE
        self.MEAN_DIFFTIMES = DEFAULT_VALUE
        self.MEDIAN_DIFFTIMES = DEFAULT_VALUE
        self.MIN_DIFFTIMES = DEFAULT_VALUE
        self.MAX_DIFFTIMES = DEFAULT_VALUE
        self.MEAN_SCALED_DIFFTIMES = DEFAULT_VALUE
        # beahavior-based features
        self.SIG_SPACES = False
        self.SWITCHING_METRIC = DEFAULT_VALUE
        self.TRANSIENTS = False
        self.CNT_ZEROS = DEFAULT_VALUE
        self.CNT_NZ_DISTRIBUTION = DEFAULT_VALUE
        self.BIGGEST_CNT_1_SEC = DEFAULT_VALUE
        self.DIRECTIONS = DEFAULT_VALUE
        self.PERIODICITY = False
        self.VAL = 0
        self.TIME = 0
        # frequency-based features
        self.MIN_POWER = DEFAULT_VALUE
        self.MAX_POWER = DEFAULT_VALUE
        self.MIN_POWER_FREQ = DEFAULT_VALUE
        self.MAX_POWER_FREQ = DEFAULT_VALUE
        self.POWER_MEAN = DEFAULT_VALUE
        self.POWER_STD = DEFAULT_VALUE
        self.POWER_MODE = DEFAULT_VALUE
        self.SPECTRAL_ENERGY = DEFAULT_VALUE
        self.SPECTRAL_ENTROPY = DEFAULT_VALUE
        self.SPECTRAL_KURTOSIS = DEFAULT_VALUE
        self.SPECTRAL_SKEWNESS = DEFAULT_VALUE
        self.SPECTRAL_ROLLOFF = DEFAULT_VALUE
        self.SPECTRAL_CENTROID = DEFAULT_VALUE
        self.SPECTRAL_SPREAD = DEFAULT_VALUE
        self.SPECTRAL_SLOPE = DEFAULT_VALUE
        self.SPECTRAL_CREST = DEFAULT_VALUE
        self.SPECTRAL_FLUX = DEFAULT_VALUE
        self.SPECTRAL_BANDWIDTH = DEFAULT_VALUE
        self.PERIODICITY_SCDF = False
        #extension based on direction
        self.MEAN_0 = DEFAULT_VALUE_DIR
        self.MEDIAN_0 = DEFAULT_VALUE_DIR
        self.STDEV_0 = DEFAULT_VALUE_DIR
        self.VAR_0 = DEFAULT_VALUE_DIR
        self.BURSTINESS_0 = DEFAULT_VALUE_DIR
        self.Q1_0 = DEFAULT_VALUE_DIR
        self.Q3_0 = DEFAULT_VALUE_DIR
        self.MIN_0 = DEFAULT_VALUE_DIR
        self.MAX_0 = DEFAULT_VALUE_DIR
        self.MIN_MINUS_MAX_0 = DEFAULT_VALUE_DIR
        self.MODE_0 = DEFAULT_VALUE_DIR
        self.COEFFICIENT_OF_VARIATION_0 = DEFAULT_VALUE_DIR
        self.AVERAGE_DISPERSION_0 = DEFAULT_VALUE_DIR
        self.PERCENT_DEVIATION_0 = DEFAULT_VALUE_DIR
        self.ROOT_MEAN_SQUARE_0 = DEFAULT_VALUE_DIR
        self.PERCENT_BELOW_MEAN_0 = DEFAULT_VALUE_DIR
        self.PERCENT_ABOVE_MEAN_0 = DEFAULT_VALUE_DIR
        self.PEARSON_SK1_SKEWNESS_0 = DEFAULT_VALUE_DIR
        self.PEARSON_SK2_SKEWNESS_0 = DEFAULT_VALUE_DIR
        self.FISHER_MI_3_SKEWNESS_0 = DEFAULT_VALUE_DIR
        self.FISHER_PEARSON_g1_SKEWNESS_0 = DEFAULT_VALUE_DIR
        self.FISHER_PEARSON_G1_SKEWNESS_0 = DEFAULT_VALUE_DIR
        self.GALTON_SKEWNESS_0 = DEFAULT_VALUE_DIR
        self.KURTOSIS_0 = DEFAULT_VALUE_DIR
        self.ENTROPY_0 = DEFAULT_VALUE_DIR
        self.SCALED_ENTROPY_0 = DEFAULT_VALUE_DIR
        self.HURST_EXPONENT_0 = DEFAULT_VALUE_DIR
        self.BENFORD_LAW_PRESENTED_0 = False
        self.P_BENFORD_0 = DEFAULT_VALUE_DIR
        self.NORMAL_DISTRIBUTION_0 = DEFAULT_VALUE_DIR
        self.CNT_DISTRIBUTION_0 = DEFAULT_VALUE_DIR
        self.TIME_DISTRIBUTION_0 = DEFAULT_VALUE_DIR
        self.AREA_VALUES_DISTRIBUTION_0 = DEFAULT_VALUE_DIR
        self.MEAN_SCALED_TIME_0 = DEFAULT_VALUE_DIR
        self.MEDIAN_SCALED_TIME_0 = DEFAULT_VALUE_DIR
        self.Q1_SCALED_TIME_0 = DEFAULT_VALUE_DIR
        self.Q3_SCALED_TIME_0 = DEFAULT_VALUE_DIR
        self.DURATION_0 = DEFAULT_VALUE_DIR
        self.MEAN_DIFFTIMES_0 = DEFAULT_VALUE_DIR
        self.MEDIAN_DIFFTIMES_0 = DEFAULT_VALUE_DIR
        self.MIN_DIFFTIMES_0 = DEFAULT_VALUE_DIR
        self.MAX_DIFFTIMES_0 = DEFAULT_VALUE_DIR
        self.MEAN_SCALED_DIFFTIMES_0 = DEFAULT_VALUE_DIR
        self.SIG_SPACES_0 = False
        self.SWITCHING_METRIC_0 = DEFAULT_VALUE_DIR
        self.TRANSIENTS_0 = False
        self.CNT_ZEROS_0 = DEFAULT_VALUE_DIR
        self.CNT_NZ_DISTRIBUTION_0 = DEFAULT_VALUE_DIR
        self.BIGGEST_CNT_1_SEC_0 = DEFAULT_VALUE_DIR
        self.PERIODICITY_0 = False
        self.VAL_0 = 0
        self.TIME_0 = 0
        self.MEAN_1 = DEFAULT_VALUE_DIR
        self.MEDIAN_1 = DEFAULT_VALUE_DIR
        self.STDEV_1 = DEFAULT_VALUE_DIR
        self.VAR_1 = DEFAULT_VALUE_DIR
        self.BURSTINESS_1 = DEFAULT_VALUE_DIR
        self.Q1_1 = DEFAULT_VALUE_DIR
        self.Q3_1 = DEFAULT_VALUE_DIR
        self.MIN_1 = DEFAULT_VALUE_DIR
        self.MAX_1 = DEFAULT_VALUE_DIR
        self.MIN_MINUS_MAX_1 = DEFAULT_VALUE_DIR
        self.MODE_1 = DEFAULT_VALUE_DIR
        self.COEFFICIENT_OF_VARIATION_1 = DEFAULT_VALUE_DIR
        self.AVERAGE_DISPERSION_1 = DEFAULT_VALUE_DIR
        self.PERCENT_DEVIATION_1 = DEFAULT_VALUE_DIR
        self.ROOT_MEAN_SQUARE_1 = DEFAULT_VALUE_DIR
        self.PERCENT_BELOW_MEAN_1 = DEFAULT_VALUE_DIR
        self.PERCENT_ABOVE_MEAN_1 = DEFAULT_VALUE_DIR
        self.PEARSON_SK1_SKEWNESS_1 = DEFAULT_VALUE_DIR
        self.PEARSON_SK2_SKEWNESS_1 = DEFAULT_VALUE_DIR
        self.FISHER_MI_3_SKEWNESS_1 = DEFAULT_VALUE_DIR
        self.FISHER_PEARSON_g1_SKEWNESS_1 = DEFAULT_VALUE_DIR
        self.FISHER_PEARSON_G1_SKEWNESS_1 = DEFAULT_VALUE_DIR
        self.GALTON_SKEWNESS_1 = DEFAULT_VALUE_DIR
        self.KURTOSIS_1 = DEFAULT_VALUE_DIR
        self.ENTROPY_1 = DEFAULT_VALUE_DIR
        self.SCALED_ENTROPY_1 = DEFAULT_VALUE_DIR
        self.HURST_EXPONENT_1 = DEFAULT_VALUE_DIR
        self.BENFORD_LAW_PRESENTED_1 = False
        self.P_BENFORD_1 = DEFAULT_VALUE_DIR
        self.NORMAL_DISTRIBUTION_1 = DEFAULT_VALUE_DIR
        self.CNT_DISTRIBUTION_1 = DEFAULT_VALUE_DIR
        self.TIME_DISTRIBUTION_1 = DEFAULT_VALUE_DIR
        self.AREA_VALUES_DISTRIBUTION_1 = DEFAULT_VALUE_DIR
        self.MEAN_SCALED_TIME_1 = DEFAULT_VALUE_DIR
        self.MEDIAN_SCALED_TIME_1 = DEFAULT_VALUE_DIR
        self.Q1_SCALED_TIME_1 = DEFAULT_VALUE_DIR
        self.Q3_SCALED_TIME_1 = DEFAULT_VALUE_DIR
        self.DURATION_1 = DEFAULT_VALUE_DIR
        self.MEAN_DIFFTIMES_1 = DEFAULT_VALUE_DIR
        self.MEDIAN_DIFFTIMES_1 = DEFAULT_VALUE_DIR
        self.MIN_DIFFTIMES_1 = DEFAULT_VALUE_DIR
        self.MAX_DIFFTIMES_1 = DEFAULT_VALUE_DIR
        self.MEAN_SCALED_DIFFTIMES_1 = DEFAULT_VALUE_DIR
        self.SIG_SPACES_1 = False
        self.SWITCHING_METRIC_1 = DEFAULT_VALUE_DIR
        self.TRANSIENTS_1 = False
        self.CNT_ZEROS_1 = DEFAULT_VALUE_DIR
        self.CNT_NZ_DISTRIBUTION_1 = DEFAULT_VALUE_DIR
        self.BIGGEST_CNT_1_SEC_1 = DEFAULT_VALUE_DIR
        self.PERIODICITY_1 = False
        self.VAL_1 = 0
        self.TIME_1 = 0
        
    def extend_with_0_direction(self, ts_plugin_0):
        self.MEDIAN_0 = ts_plugin_0.MEDIAN_0
        self.STDEV_0 =             ts_plugin_0.STDEV_0
        self.VAR_0 =             ts_plugin_0.VAR_0
        self.BURSTINESS_0 =             ts_plugin_0.BURSTINESS_0
        self.Q1_0 =             ts_plugin_0.Q1_0
        self.Q3_0 =             ts_plugin_0.Q3_0
        self.MIN_0 =             ts_plugin_0.MIN_0
        self.MAX_0 =             ts_plugin_0.MAX_0
        self.MIN_MINUS_MAX_0 =             ts_plugin_0.MIN_MINUS_MAX_0
        self.MODE_0 =             ts_plugin_0.MODE_0
        self.COEFFICIENT_OF_VARIATION_0 =             ts_plugin_0.COEFFICIENT_OF_VARIATION_0
        self.AVERAGE_DISPERSION_0 =             ts_plugin_0.AVERAGE_DISPERSION_0
        self.PERCENT_DEVIATION_0 =             ts_plugin_0.PERCENT_DEVIATION_0
        self.ROOT_MEAN_SQUARE_0 =             ts_plugin_0.ROOT_MEAN_SQUARE_0
        self.PERCENT_BELOW_MEAN_0 =             ts_plugin_0.PERCENT_BELOW_MEAN_0
        self.PERCENT_ABOVE_MEAN_0 =             ts_plugin_0.PERCENT_ABOVE_MEAN_0
        self.PEARSON_SK1_SKEWNESS_0 =             ts_plugin_0.PEARSON_SK1_SKEWNESS_0
        self.PEARSON_SK2_SKEWNESS_0 =             ts_plugin_0.PEARSON_SK2_SKEWNESS_0
        self.FISHER_MI_3_SKEWNESS_0 =             ts_plugin_0.FISHER_MI_3_SKEWNESS_0
        self.FISHER_PEARSON_g1_SKEWNESS_0 =             ts_plugin_0.FISHER_PEARSON_g1_SKEWNESS_0
        self.FISHER_PEARSON_G1_SKEWNESS_0 =             ts_plugin_0.FISHER_PEARSON_G1_SKEWNESS_0
        self.GALTON_SKEWNESS_0 =             ts_plugin_0.GALTON_SKEWNESS_0
        self.KURTOSIS_0 =             ts_plugin_0.KURTOSIS_0
        self.ENTROPY_0 =             ts_plugin_0.ENTROPY_0
        self.SCALED_ENTROPY_0 =             ts_plugin_0.SCALED_ENTROPY_0
        self.HURST_EXPONENT_0 =             ts_plugin_0.HURST_EXPONENT_0
        self.BENFORD_LAW_PRESENTED_0 =             ts_plugin_0.BENFORD_LAW_PRESENTED_0
        self.P_BENFORD_0 =             ts_plugin_0.P_BENFORD_0
        self.NORMAL_DISTRIBUTION_0 =             ts_plugin_0.NORMAL_DISTRIBUTION_0
        self.CNT_DISTRIBUTION_0 =             ts_plugin_0.CNT_DISTRIBUTION_0
        self.TIME_DISTRIBUTION_0 =             ts_plugin_0.TIME_DISTRIBUTION_0
        self.AREA_VALUES_DISTRIBUTION_0 =             ts_plugin_0.AREA_VALUES_DISTRIBUTION_0
        self.MEAN_SCALED_TIME_0 =             ts_plugin_0.MEAN_SCALED_TIME_0
        self.MEDIAN_SCALED_TIME_0 =             ts_plugin_0.MEDIAN_SCALED_TIME_0
        self.Q1_SCALED_TIME_0 =             ts_plugin_0.Q1_SCALED_TIME_0
        self.Q3_SCALED_TIME_0 =             ts_plugin_0.Q3_SCALED_TIME_0
        self.DURATION_0 =             ts_plugin_0.DURATION_0
        self.MEAN_DIFFTIMES_0 =             ts_plugin_0.MEAN_DIFFTIMES_0
        self.MEDIAN_DIFFTIMES_0 =             ts_plugin_0.MEDIAN_DIFFTIMES_0
        self.MIN_DIFFTIMES_0 =             ts_plugin_0.MIN_DIFFTIMES_0
        self.MAX_DIFFTIMES_0 =             ts_plugin_0.MAX_DIFFTIMES_0
        self.MEAN_SCALED_DIFFTIMES_0 =             ts_plugin_0.MEAN_SCALED_DIFFTIMES_0
        self.SIG_SPACES_0 =             ts_plugin_0.SIG_SPACES_0
        self.SWITCHING_METRIC_0 =             ts_plugin_0.SWITCHING_METRIC_0
        self.TRANSIENTS_0 =             ts_plugin_0.TRANSIENTS_0
        self.CNT_ZEROS_0 =             ts_plugin_0.CNT_ZEROS_0
        self.CNT_NZ_DISTRIBUTION_0 =             ts_plugin_0.CNT_NZ_DISTRIBUTION_0
        self.BIGGEST_CNT_1_SEC_0 =             ts_plugin_0.BIGGEST_CNT_1_SEC_0
        self.PERIODICITY_0 =             ts_plugin_0.PERIODICITY_0
        self.VAL_0 =             ts_plugin_0.VAL_0
        self.TIME_0 =             ts_plugin_0.TIME_0

    def extend_with_1_direction(self, ts_plugin_1):
        self.MEDIAN_1 = ts_plugin_1.MEDIAN
        self.STDEV_1 =             ts_plugin_1.STDEV
        self.VAR_1 =             ts_plugin_1.VAR
        self.BURSTINESS_1 =             ts_plugin_1.BURSTINESS
        self.Q1_1 =             ts_plugin_1.Q1
        self.Q3_1 =             ts_plugin_1.Q3
        self.MIN_1 =             ts_plugin_1.MIN
        self.MAX_1 =             ts_plugin_1.MAX
        self.MIN_MINUS_MAX_1 =             ts_plugin_1.MIN_MINUS_MAX
        self.MODE_1 =             ts_plugin_1.MODE
        self.COEFFICIENT_OF_VARIATION_1 =             ts_plugin_1.COEFFICIENT_OF_VARIATION
        self.AVERAGE_DISPERSION_1 =             ts_plugin_1.AVERAGE_DISPERSION
        self.PERCENT_DEVIATION_1 =             ts_plugin_1.PERCENT_DEVIATION
        self.ROOT_MEAN_SQUARE_1 =             ts_plugin_1.ROOT_MEAN_SQUARE
        self.PERCENT_BELOW_MEAN_1 =             ts_plugin_1.PERCENT_BELOW_MEAN
        self.PERCENT_ABOVE_MEAN_1 =             ts_plugin_1.PERCENT_ABOVE_MEAN
        self.PEARSON_SK1_SKEWNESS_1 =             ts_plugin_1.PEARSON_SK1_SKEWNESS
        self.PEARSON_SK2_SKEWNESS_1 =             ts_plugin_1.PEARSON_SK2_SKEWNESS
        self.FISHER_MI_3_SKEWNESS_1 =             ts_plugin_1.FISHER_MI_3_SKEWNESS
        self.FISHER_PEARSON_g1_SKEWNESS_1 =             ts_plugin_1.FISHER_PEARSON_g1_SKEWNESS
        self.FISHER_PEARSON_G1_SKEWNESS_1 =             ts_plugin_1.FISHER_PEARSON_G1_SKEWNESS
        self.GALTON_SKEWNESS_1 =             ts_plugin_1.GALTON_SKEWNESS
        self.KURTOSIS_1 =             ts_plugin_1.KURTOSIS
        self.ENTROPY_1 =             ts_plugin_1.ENTROPY
        self.SCALED_ENTROPY_1 =             ts_plugin_1.SCALED_ENTROPY
        self.HURST_EXPONENT_1 =             ts_plugin_1.HURST_EXPONENT
        self.BENFORD_LAW_PRESENTED_1 =             ts_plugin_1.BENFORD_LAW_PRESENTED
        self.P_BENFORD_1 =             ts_plugin_1.P_BENFORD
        self.NORMAL_DISTRIBUTION_1 =             ts_plugin_1.NORMAL_DISTRIBUTION
        self.CNT_DISTRIBUTION_1 =             ts_plugin_1.CNT_DISTRIBUTION
        self.TIME_DISTRIBUTION_1 =             ts_plugin_1.TIME_DISTRIBUTION
        self.AREA_VALUES_DISTRIBUTION_1 =             ts_plugin_1.AREA_VALUES_DISTRIBUTION
        self.MEAN_SCALED_TIME_1 =             ts_plugin_1.MEAN_SCALED_TIME
        self.MEDIAN_SCALED_TIME_1 =             ts_plugin_1.MEDIAN_SCALED_TIME
        self.Q1_SCALED_TIME_1 =             ts_plugin_1.Q1_SCALED_TIME
        self.Q3_SCALED_TIME_1 =             ts_plugin_1.Q3_SCALED_TIME
        self.DURATION_1 =             ts_plugin_1.DURATION
        self.MEAN_DIFFTIMES_1 =             ts_plugin_1.MEAN_DIFFTIMES
        self.MEDIAN_DIFFTIMES_1 =             ts_plugin_1.MEDIAN_DIFFTIMES
        self.MIN_DIFFTIMES_1 =             ts_plugin_1.MIN_DIFFTIMES
        self.MAX_DIFFTIMES_1 =             ts_plugin_1.MAX_DIFFTIMES
        self.MEAN_SCALED_DIFFTIMES_1 =             ts_plugin_1.MEAN_SCALED_DIFFTIMES
        self.SIG_SPACES_1 =             ts_plugin_1.SIG_SPACES
        self.SWITCHING_METRIC_1 =             ts_plugin_1.SWITCHING_METRIC
        self.TRANSIENTS_1 =             ts_plugin_1.TRANSIENTS
        self.CNT_ZEROS_1 =             ts_plugin_1.CNT_ZEROS
        self.CNT_NZ_DISTRIBUTION_1 =             ts_plugin_1.CNT_NZ_DISTRIBUTION
        self.BIGGEST_CNT_1_SEC_1 =             ts_plugin_1.BIGGEST_CNT_1_SEC
        self.PERIODICITY_1 =             ts_plugin_1.PERIODICITY
        self.VAL_1 =             ts_plugin_1.VAL
        self.TIME_1 =             ts_plugin_1.TIME


    def export(self):
        return [
            self.DST_IP,
            self.SRC_IP,
            self.PACKETS,
            self.PACKETS_REV,
            self.BYTES,
            self.BYTES_REV,
            self.TIME_FIRST,
            self.TIME_LAST,
            self.DST_PORT,
            self.SRC_PORT,
            self.MEAN,
            self.MEDIAN,
            self.STDEV,
            self.VAR,
            self.BURSTINESS,
            self.Q1,
            self.Q3,
            self.MIN,
            self.MAX,
            self.MIN_MINUS_MAX,
            self.MODE,
            self.COEFFICIENT_OF_VARIATION,
            self.AVERAGE_DISPERSION,
            self.PERCENT_DEVIATION,
            self.ROOT_MEAN_SQUARE,
            self.PERCENT_BELOW_MEAN,
            self.PERCENT_ABOVE_MEAN,
            self.PEARSON_SK1_SKEWNESS,
            self.PEARSON_SK2_SKEWNESS,
            self.FISHER_MI_3_SKEWNESS,
            self.FISHER_PEARSON_g1_SKEWNESS,
            self.FISHER_PEARSON_G1_SKEWNESS,
            self.GALTON_SKEWNESS,
            self.KURTOSIS,
            self.ENTROPY,
            self.SCALED_ENTROPY,
            self.HURST_EXPONENT,
            self.BENFORD_LAW_PRESENTED,
            self.P_BENFORD,
            self.NORMAL_DISTRIBUTION,
            self.CNT_DISTRIBUTION,
            self.TIME_DISTRIBUTION,
            self.AREA_VALUES_DISTRIBUTION,
            self.MEAN_SCALED_TIME,
            self.MEDIAN_SCALED_TIME,
            self.Q1_SCALED_TIME,
            self.Q3_SCALED_TIME,
            self.DURATION,
            self.MEAN_DIFFTIMES,
            self.MEDIAN_DIFFTIMES,
            self.MIN_DIFFTIMES,
            self.MAX_DIFFTIMES,
            self.MEAN_SCALED_DIFFTIMES,
            self.SIG_SPACES,
            self.SWITCHING_METRIC,
            self.TRANSIENTS,
            self.CNT_ZEROS,
            self.CNT_NZ_DISTRIBUTION,
            self.BIGGEST_CNT_1_SEC,
            self.DIRECTIONS,
            self.PERIODICITY,
            self.VAL,
            self.TIME,
            self.MIN_POWER,
            self.MAX_POWER,
            self.MIN_POWER_FREQ,
            self.MAX_POWER_FREQ,
            self.POWER_MEAN,
            self.POWER_STD,
            self.POWER_MODE,
            self.SPECTRAL_ENERGY,
            self.SPECTRAL_ENTROPY,
            self.SPECTRAL_KURTOSIS,
            self.SPECTRAL_SKEWNESS,
            self.SPECTRAL_ROLLOFF,
            self.SPECTRAL_CENTROID,
            self.SPECTRAL_SPREAD,
            self.SPECTRAL_SLOPE,
            self.SPECTRAL_CREST,
            self.SPECTRAL_FLUX,
            self.SPECTRAL_BANDWIDTH,
            self.PERIODICITY_SCDF,
            # self.MEAN_0,
            # self.MEDIAN_0,
            # self.STDEV_0,
            # self.VAR_0,
            # self.BURSTINESS_0,
            # self.Q1_0,
            # self.Q3_0,
            # self.MIN_0,
            # self.MAX_0,
            # self.MIN_MINUS_MAX_0,
            # self.MODE_0,
            # self.COEFFICIENT_OF_VARIATION_0,
            # self.AVERAGE_DISPERSION_0,
            # self.PERCENT_DEVIATION_0,
            # self.ROOT_MEAN_SQUARE_0,
            # self.PERCENT_BELOW_MEAN_0,
            # self.PERCENT_ABOVE_MEAN_0,
            # self.PEARSON_SK1_SKEWNESS_0,
            # self.PEARSON_SK2_SKEWNESS_0,
            # self.FISHER_MI_3_SKEWNESS_0,
            # self.FISHER_PEARSON_g1_SKEWNESS_0,
            # self.FISHER_PEARSON_G1_SKEWNESS_0,
            # self.GALTON_SKEWNESS_0,
            # self.KURTOSIS_0,
            # self.ENTROPY_0,
            # self.SCALED_ENTROPY_0,
            # self.HURST_EXPONENT_0,
            # self.BENFORD_LAW_PRESENTED_0,
            # self.P_BENFORD_0,
            # self.NORMAL_DISTRIBUTION_0,
            # self.CNT_DISTRIBUTION_0,
            # self.TIME_DISTRIBUTION_0,
            # self.AREA_VALUES_DISTRIBUTION_0,
            # self.MEAN_SCALED_TIME_0,
            # self.MEDIAN_SCALED_TIME_0,
            # self.Q1_SCALED_TIME_0,
            # self.Q3_SCALED_TIME_0,
            # self.DURATION_0,
            # self.MEAN_DIFFTIMES_0,
            # self.MEDIAN_DIFFTIMES_0,
            # self.MIN_DIFFTIMES_0,
            # self.MAX_DIFFTIMES_0,
            # self.MEAN_SCALED_DIFFTIMES_0,
            # self.SIG_SPACES_0,
            # self.SWITCHING_METRIC_0,
            # self.TRANSIENTS_0,
            # self.CNT_ZEROS_0,
            # self.CNT_NZ_DISTRIBUTION_0,
            # self.BIGGEST_CNT_1_SEC_0,
            # self.PERIODICITY_0,
            # self.VAL_0,
            # self.TIME_0,
            # self.MEAN_1,
            # self.MEDIAN_1,
            # self.STDEV_1,
            # self.VAR_1,
            # self.BURSTINESS_1,
            # self.Q1_1,
            # self.Q3_1,
            # self.MIN_1,
            # self.MAX_1,
            # self.MIN_MINUS_MAX_1,
            # self.MODE_1,
            # self.COEFFICIENT_OF_VARIATION_1,
            # self.AVERAGE_DISPERSION_1,
            # self.PERCENT_DEVIATION_1,
            # self.ROOT_MEAN_SQUARE_1,
            # self.PERCENT_BELOW_MEAN_1,
            # self.PERCENT_ABOVE_MEAN_1,
            # self.PEARSON_SK1_SKEWNESS_1,
            # self.PEARSON_SK2_SKEWNESS_1,
            # self.FISHER_MI_3_SKEWNESS_1,
            # self.FISHER_PEARSON_g1_SKEWNESS_1,
            # self.FISHER_PEARSON_G1_SKEWNESS_1,
            # self.GALTON_SKEWNESS_1,
            # self.KURTOSIS_1,
            # self.ENTROPY_1,
            # self.SCALED_ENTROPY_1,
            # self.HURST_EXPONENT_1,
            # self.BENFORD_LAW_PRESENTED_1,
            # self.P_BENFORD_1,
            # self.NORMAL_DISTRIBUTION_1,
            # self.CNT_DISTRIBUTION_1,
            # self.TIME_DISTRIBUTION_1,
            # self.AREA_VALUES_DISTRIBUTION_1,
            # self.MEAN_SCALED_TIME_1,
            # self.MEDIAN_SCALED_TIME_1,
            # self.Q1_SCALED_TIME_1,
            # self.Q3_SCALED_TIME_1,
            # self.DURATION_1,
            # self.MEAN_DIFFTIMES_1,
            # self.MEDIAN_DIFFTIMES_1,
            # self.MIN_DIFFTIMES_1,
            # self.MAX_DIFFTIMES_1,
            # self.MEAN_SCALED_DIFFTIMES_1,
            # self.SIG_SPACES_1,
            # self.SWITCHING_METRIC_1,
            # self.TRANSIENTS_1,
            # self.CNT_ZEROS_1,
            # self.CNT_NZ_DISTRIBUTION_1,
            # self.BIGGEST_CNT_1_SEC_1,
            # self.PERIODICITY_1,
            # self.VAL_1,
            # self.TIME_1,
        ]

HEADER = [
    "DST_IP",
    "SRC_IP",
    "PACKETS",
    "PACKETS_REV",
    "BYTES",
    "BYTES_REV",
    "TIME_FIRST",
    "TIME_LAST",
    "DST_PORT",
    "SRC_PORT",
    "MEAN",
    "MEDIAN",
    "STDEV",
    "VAR",
    "BURSTINESS",
    "Q1",
    "Q3",
    "MIN",
    "MAX",
    "MIN_MINUS_MAX",
    "MODE",
    "COEFFICIENT_OF_VARIATION",
    "AVERAGE_DISPERSION",
    "PERCENT_DEVIATION",
    "ROOT_MEAN_SQUARE",
    "PERCENT_BELOW_MEAN",
    "PERCENT_ABOVE_MEAN",
    "PEARSON_SK1_SKEWNESS",
    "PEARSON_SK2_SKEWNESS",
    "FISHER_MI_3_SKEWNESS",
    "FISHER_PEARSON_g1_SKEWNESS",
    "FISHER_PEARSON_G1_SKEWNESS",
    "GALTON_SKEWNESS",
    "KURTOSIS",
    "ENTROPY",
    "SCALED_ENTROPY",
    "HURST_EXPONENT",
    "BENFORD_LAW_PRESENTED",
    "P_BENFORD",
    "NORMAL_DISTRIBUTION",
    "CNT_DISTRIBUTION",
    "TIME_DISTRIBUTION",
    "AREA_VALUES_DISTRIBUTION",
    "MEAN_SCALED_TIME",
    "MEDIAN_SCALED_TIME",
    "Q1_SCALED_TIME",
    "Q3_SCALED_TIME",
    "DURATION",
    "MEAN_DIFFTIMES",
    "MEDIAN_DIFFTIMES",
    "MIN_DIFFTIMES",
    "MAX_DIFFTIMES",
    "MEAN_SCALED_DIFFTIMES",
    "SIG_SPACES",
    "SWITCHING_METRIC",
    "TRANSIENTS",
    "CNT_ZEROS",
    "CNT_NZ_DISTRIBUTION",
    "BIGGEST_CNT_1_SEC",
    "DIRECTIONS",
    "PERIODICITY",
    "VAL",
    "TIME",
    "MIN_POWER",
    "MAX_POWER",
    "MIN_POWER_FREQ",
    "MAX_POWER_FREQ",
    "POWER_MEAN",
    "POWER_STD",
    "POWER_MODE",
    "SPECTRAL_ENERGY",
    "SPECTRAL_ENTROPY",
    "SPECTRAL_KURTOSIS",
    "SPECTRAL_SKEWNESS",
    "SPECTRAL_ROLLOFF",
    "SPECTRAL_CENTROID",
    "SPECTRAL_SPREAD",
    "SPECTRAL_SLOPE",
    "SPECTRAL_CREST",
    "SPECTRAL_FLUX",
    "SPECTRAL_BANDWIDTH",
    "PERIODICITY_SCDF",    
    # "MEAN_0",
    # "MEDIAN_0",
    # "STDEV_0",
    # "VAR_0",
    # "BURSTINESS_0",
    # "Q1_0",
    # "Q3_0",
    # "MIN_0",
    # "MAX_0",
    # "MIN_MINUS_MAX_0",
    # "MODE_0",
    # "COEFFICIENT_OF_VARIATION_0",
    # "AVERAGE_DISPERSION_0",
    # "PERCENT_DEVIATION_0",
    # "ROOT_MEAN_SQUARE_0",
    # "PERCENT_BELOW_MEAN_0",
    # "PERCENT_ABOVE_MEAN_0",
    # "PEARSON_SK1_SKEWNESS_0",
    # "PEARSON_SK2_SKEWNESS_0",
    # "FISHER_MI_3_SKEWNESS_0",
    # "FISHER_PEARSON_g1_SKEWNESS_0",
    # "FISHER_PEARSON_G1_SKEWNESS_0",
    # "GALTON_SKEWNESS_0",
    # "KURTOSIS_0",
    # "ENTROPY_0",
    # "SCALED_ENTROPY_0",
    # "HURST_EXPONENT_0",
    # "BENFORD_LAW_PRESENTED_0",
    # "P_BENFORD_0",
    # "NORMAL_DISTRIBUTION_0",
    # "CNT_DISTRIBUTION_0",
    # "TIME_DISTRIBUTION_0",
    # "AREA_VALUES_DISTRIBUTION_0",
    # "MEAN_SCALED_TIME_0",
    # "MEDIAN_SCALED_TIME_0",
    # "Q1_SCALED_TIME_0",
    # "Q3_SCALED_TIME_0",
    # "DURATION_0",
    # "MEAN_DIFFTIMES_0",
    # "MEDIAN_DIFFTIMES_0",
    # "MIN_DIFFTIMES_0",
    # "MAX_DIFFTIMES_0",
    # "MEAN_SCALED_DIFFTIMES_0",
    # "SIG_SPACES_0",
    # "SWITCHING_METRIC_0",
    # "TRANSIENTS_0",
    # "CNT_ZEROS_0",
    # "CNT_NZ_DISTRIBUTION_0",
    # "BIGGEST_CNT_1_SEC_0",
    # "PERIODICITY_0",
    # "VAL_0",
    # "TIME_0",
    # "MEAN_1",
    # "MEDIAN_1",
    # "STDEV_1",
    # "VAR_1",
    # "BURSTINESS_1",
    # "Q1_1",
    # "Q3_1",
    # "MIN_1",
    # "MAX_1",
    # "MIN_MINUS_MAX_1",
    # "MODE_1",
    # "COEFFICIENT_OF_VARIATION_1",
    # "AVERAGE_DISPERSION_1",
    # "PERCENT_DEVIATION_1",
    # "ROOT_MEAN_SQUARE_1",
    # "PERCENT_BELOW_MEAN_1",
    # "PERCENT_ABOVE_MEAN_1",
    # "PEARSON_SK1_SKEWNESS_1",
    # "PEARSON_SK2_SKEWNESS_1",
    # "FISHER_MI_3_SKEWNESS_1",
    # "FISHER_PEARSON_g1_SKEWNESS_1",
    # "FISHER_PEARSON_G1_SKEWNESS_1",
    # "GALTON_SKEWNESS_1",
    # "KURTOSIS_1",
    # "ENTROPY_1",
    # "SCALED_ENTROPY_1",
    # "HURST_EXPONENT_1",
    # "BENFORD_LAW_PRESENTED_1",
    # "P_BENFORD_1",
    # "NORMAL_DISTRIBUTION_1",
    # "CNT_DISTRIBUTION_1",
    # "TIME_DISTRIBUTION_1",
    # "AREA_VALUES_DISTRIBUTION_1",
    # "MEAN_SCALED_TIME_1",
    # "MEDIAN_SCALED_TIME_1",
    # "Q1_SCALED_TIME_1",
    # "Q3_SCALED_TIME_1",
    # "DURATION_1",
    # "MEAN_DIFFTIMES_1",
    # "MEDIAN_DIFFTIMES_1",
    # "MIN_DIFFTIMES_1",
    # "MAX_DIFFTIMES_1",
    # "MEAN_SCALED_DIFFTIMES_1",
    # "SIG_SPACES_1",
    # "SWITCHING_METRIC_1",
    # "TRANSIENTS_1",
    # "CNT_ZEROS_1",
    # "CNT_NZ_DISTRIBUTION_1",
    # "BIGGEST_CNT_1_SEC_1",
    # "PERIODICITY_1",
    # "VAL_1",
    # "TIME_1",
]


INACTIVE_TIMEOUT = 65
ACTIVE_TIMEOUT = 300


T = 300  # duration of time series in seconds
Pmin = 1  # minimum period in seconds
Pmax = T/2  # maximum period in seconds
fmin = 1/Pmax  # minimum frequency in Hz
fmax = 1/Pmin  # maximum frequency in Hz
N = 5000 # frequency resolution -- This will depend on the desired precision of the periodogram and the amount of computational resources you have available.
# fmin = 0  # minimum frequency in Hz
# fmax = 1  # maximum frequency in Hz
df = (fmax - fmin)/N  # frequency resolution
FREQUENCY = np.arange(fmin, fmax, df)



# statistics features
def get_basic_stats(data: np.ndarray, plugin: TimeSeriesPlugin):
    """Compute basic statistical features.

    Args:
        data (np.array): Time series data.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    plugin.MEAN = statistics.mean(data)
    plugin.MEDIAN = statistics.median(data)
    if len(data) == 1:
        plugin.STDEV = data[0]
    elif len(data) == 0:
        plugin.STDEV = 0  # type: ignore
    else:
        try:
            plugin.STDEV = statistics.stdev(data)
        except:
            plugin.STDEV = statistics.stdev(data[:1000])
    if len(data) < 2:
        plugin.VAR = 0
    else:
        plugin.VAR = statistics.variance(data, xbar=plugin.MEAN)
    plugin.BURSTINESS = (plugin.STDEV - plugin.MEAN) / (plugin.STDEV + plugin.MEAN)
    plugin.MODE = np.bincount(data).argmax()  # type: ignore
    # mode is most frequent value of data
    plugin.Q1 = np.percentile(data, 25)  # type: ignore
    plugin.Q3 = np.percentile(data, 75)  # type: ignore
    if plugin.MEAN == 0:
        plugin.COEFFICIENT_OF_VARIATION = 0
    else:
        plugin.COEFFICIENT_OF_VARIATION = (plugin.STDEV / plugin.MEAN) * 100
    plugin.MIN = data.min()
    plugin.MAX = data.max()
    plugin.MIN_MINUS_MAX = plugin.MAX - plugin.MIN
    new_data = []
    for d in data:
        new_data.append(abs(d - plugin.MEAN))
    plugin.AVERAGE_DISPERSION = statistics.mean(new_data)
    if plugin.MEAN == 0:
        plugin.PERCENT_DEVIATION = 0
    else:
        plugin.PERCENT_DEVIATION = (plugin.AVERAGE_DISPERSION / plugin.MEAN) * 100
    if len(data) == 0:
        plugin.ROOT_MEAN_SQUARE = 0
    else:
        plugin.ROOT_MEAN_SQUARE = 0  # type: ignore
        for d in data:
            plugin.ROOT_MEAN_SQUARE += math.pow(d, 2)  # type: ignore
        plugin.ROOT_MEAN_SQUARE *= 1 / len(data)  # type: ignore
        plugin.ROOT_MEAN_SQUARE = math.sqrt(plugin.ROOT_MEAN_SQUARE)  # type: ignore
    plugin.PERCENT_BELOW_MEAN = (data < plugin.MEAN).sum() / len(data)
    plugin.PERCENT_ABOVE_MEAN = (data > plugin.MEAN).sum() / len(data)


def get_entropy(data: np.ndarray, plugin: TimeSeriesPlugin):
    """Compute statistical feature called Entropy that is a scientific concept as well as
    a measurable physical property that is most commonly associated with a state of disorder,
    randomness, or uncertainty. And than scaled entropy, that is scaled by maximum entropy
    to be comparable with another results.

    Args:
        data (np.array): Time series data.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    N = len(data)
    if N == 0:
        return
    p = {}
    for d in data:
        if d not in p:
            p[d] = 0
        p[d] += 1
    plugin.ENTROPY = 0  # type: ignore
    for d in p:
        prob = p[d] / N
        plugin.ENTROPY += prob * math.log2(prob)
    if plugin.ENTROPY != 0:
        plugin.ENTROPY = -plugin.ENTROPY
    if N == 1:
        plugin.SCALED_ENTROPY = 0  # type: ignore
    else:
        plugin.SCALED_ENTROPY = plugin.ENTROPY / (-math.log2(1 / N))  # type: ignore


def get_skewness(data: np.ndarray, hist_data: dict, plugin: TimeSeriesPlugin):
    """Compute statistic feature called Skewness that is a measure of the asymmetry of
    the probability distribution of a real-valued random variable about its mean. The
    skewness value can be positive, zero, negative, or undefined.

    Args:
        data (np.array): Time series data.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    # Pearson's Skewness formula:
    # sk1 = (X_ - Mo) / s, where X_ is mean, Mo is mode and s is standard deviation
    # sk2 = (3*X_ - Md) / s, where X_ is mean, Md is median and s is standard deviation
    if plugin.STDEV == 0:
        plugin.PEARSON_SK1_SKEWNESS = 0
        plugin.PEARSON_SK2_SKEWNESS = 0
        plugin.FISHER_MI_3_SKEWNESS = 0
        plugin.FISHER_PEARSON_g1_SKEWNESS = 0
        plugin.FISHER_PEARSON_G1_SKEWNESS = 0
        plugin.GALTON_SKEWNESS = 0
        return
    plugin.PEARSON_SK1_SKEWNESS = (plugin.MEAN - plugin.MODE) / plugin.STDEV  # type: ignore
    plugin.PEARSON_SK2_SKEWNESS = (3 * plugin.MEAN - plugin.MEDIAN) / plugin.STDEV  # type: ignore
    # Fisher's moment coefficient of skewness:
    # mi_3 = E[ ((X - X_)/ s)^3 ], where X is random variable, X_ is mean, s is standard deviation and E is expectation operator
    # mi_3 = E[ ((X - X_)/ s)^3 ] = (E[X^3] - 3*X_*s^2 - X_^3)/(s^3) = (((x1^3)*p1 + (x2^3)*p2 + ... + (xk^3)*pk) - 3*X_*s^2 - X_^3)/(s^3)
    EX = 0
    N = len(data)
    for d in hist_data:
        EX += math.pow(d, 3) * hist_data[d] / N
    plugin.FISHER_MI_3_SKEWNESS = (
        EX - 3 * plugin.MEAN * math.pow(plugin.STDEV, 2) - math.pow(plugin.MEAN, 3)  # type: ignore
    ) / (
        math.pow(plugin.STDEV, 3)  # type: ignore
    )
    # Fisher-Pearson skewness coeficient:
    # g1 = (SUM_i_n[(x_i - X_)^3/n]) / s^3
    sum_g1 = 0
    for d in data:
        sum_g1 += math.pow((d - plugin.MEAN), 3) / N
    plugin.FISHER_PEARSON_g1_SKEWNESS = sum_g1 / math.pow(plugin.STDEV, 3)  # type: ignore
    # Adjusted Fisher-Pearson skewness coeficient:
    # G1 = \frac{5}{n\sigma^3}  \sum_{i=1}^{n}\frac{(x_i - \mu)^3}{(n-1)(n-2)} - \frac{3(n-1)}{(n-2)}\left(\frac{\sum_{i=1}^{n}(x_i - \mu)^2}{n\sigma^2}\right)^{\frac{3}{2}} \)
    if N - 2 == 0:
        plugin.FISHER_PEARSON_G1_SKEWNESS = 0
    else:
        sum_G1_1 = 0
        for d in data:
            sum_G1_1 += math.pow((d - plugin.MEAN), 3) / ((N-1)*(N-2))
        
        sum_G1_2 = 0
        for d in data:
            sum_G1_2 += math.pow((d - plugin.MEAN), 2)
        
        plugin.FISHER_PEARSON_G1_SKEWNESS =  5 / (N*plugin.STDEV) * sum_G1_1    - ((3*(N-1)) / (N-2)) * math.pow((N*math.pow(plugin.STDEV, 2)), 3/2)
        # ((math.sqrt(N * (N - 1))) / (N - 2)) * plugin.FISHER_PEARSON_g1_SKEWNESS  # type: ignore
    # Galton skewness:
    # gq = (Q1 + Q3 - 2*Q2) / (Q3 - Q1), where Q1 is the lower quartile, Q3 is the upper quartile, and Q2 is the median.
    if plugin.Q3 - plugin.Q1 == 0:  # type: ignore
        plugin.GALTON_SKEWNESS = 0
    else:
        plugin.GALTON_SKEWNESS = (plugin.Q1 + plugin.Q3 - 2 * plugin.MEAN) / (  # type: ignore
            plugin.Q3 - plugin.Q1  # type: ignore
        )


def get_kurtosis(data: np.ndarray, plugin: TimeSeriesPlugin):
    """Compute statistic feature called Kurtosis that is a measure of the "tailedness"
    of the probability distribution of a real-valued random variable. Like skewness,
    kurtosis describes the shape of a probability distribution and there are different
    ways of quantifying it for a theoretical distribution and corresponding ways of
    estimating it from a sample from a population. Different measures of kurtosis may
    have different interpretations.

    Args:
        data (np.array): Time series data.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    # kurtosis = ( SUM_i_n (x_i - x_)^4 ) / ( n * s^4 ), where x_ is mean, s is standard deviation
    numerator = 0
    for d in data:
        numerator += math.pow(d - plugin.MEAN, 4)
    denominator = len(data) * math.pow(plugin.STDEV, 4)  # type: ignore
    if denominator == 0:
        plugin.KURTOSIS = 0
    else:
        plugin.KURTOSIS = numerator / denominator  # type: ignore


# hurst exponent
def get_partial_ts(ts: np.ndarray, length=5):
    partial_ts = {}
    for i in range(1, length):
        n = int(len(ts) / i)
        if n == 0:
            break
        partial_ts[n] = []
        for k in range(int(len(ts) / n)):
            partial_ts[n].append(np.array(ts[k * n : (k + 1) * n]))
    return partial_ts


def get_R_S(data: np.ndarray):
    mean = data.mean()
    Y = data - mean
    Z = np.cumsum(Y)
    R = Z.max() - Z.min()
    S = np.std(data)
    if R == 0 or S == 0:
        return 0
    return R / S


def get_avarage_R_S(partial_ts: dict):
    sums_bytes = 0
    n = len(partial_ts)
    for ts in partial_ts:
        sums_bytes += get_R_S(ts)
    return sums_bytes / n


def get_hurst_exponents(partial_ts: dict):
    """Create Anis-Lloyd correlated R/S Hurst exponent."""
    log_ns = []
    log_R_Ss_bytes = []
    for n in partial_ts:
        avarage_R_S_bytes = get_avarage_R_S(partial_ts[n])
        if avarage_R_S_bytes == 0:
            continue
        E_R_S = 0
        for i in range(1, n):
            E_R_S += (n - i) / i
        if n > 340:
            E_R_S *= 1 / math.sqrt(n * math.pi / 2)
        else:
            E_R_S *= (gamma((n - 1) / 2)) / (math.sqrt(n) * gamma(n / 2))
        log_ns.append(n)
        log_R_Ss_bytes.append(abs(avarage_R_S_bytes - E_R_S))
    if len(log_ns) == 0:
        return 1
    slope_bytes, intercept = np.polyfit(log_ns, log_R_Ss_bytes, 1)
    return 0.5 + slope_bytes


def perform_getting_hurst_exponent(bytes: np.ndarray, plugin: TimeSeriesPlugin):
    partial_ts = get_partial_ts(bytes)
    plugin.HURST_EXPONENT = get_hurst_exponents(partial_ts)


# distribution of number of data points values in time series
def is_benford_law_present(
    data: np.ndarray, hist_data: dict, plugin: TimeSeriesPlugin, THRESHOLD: float = 0.05
):
    """Benford's law says that in sets that obey the law, the number 1 appears as the leading significant
    digit about 30 percent of the time, while 9 appears as the leading significant digit less than 5 percent
    of the time. Benford's law also makes predictions about the distribution of second digits, third digits,
    digit combinations, and so on.

    In this function we try check if Benford's law is present in our data.

    Args:
        data (np.array): Time series data.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
        THRESHOLD (float, optional): Threshold for percentage occurs. Defaults to 0.05.
    """
    tmp = list(hist_data.values())
    tmp.sort(reverse=True)
    N = len(data)
    plugin.BENFORD_LAW_PRESENTED = False  # type: ignore
    for d, val in zip(np.arange(N) + 1, tmp):
        P = math.log10((d + 1) / d)
        if abs(P - (val / N)) < THRESHOLD:
            plugin.BENFORD_LAW_PRESENTED = True  # type: ignore
        else:
            plugin.BENFORD_LAW_PRESENTED = False  # type: ignore
            break


def benford_law_probability(
    data: np.ndarray, hist_data: dict, plugin: TimeSeriesPlugin
):
    """Compute the probability that the first 9 most occurs values occurs by Benford's law.

    Args:
        data (np.array): Time series data.
        hist_data (dict): Histogram of time series datapoints values.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    tmp = -1
    while len(list(hist_data.values())) < 9:
        hist_data[tmp] = 0
        tmp -= 1

    sorted_vals = list(hist_data.values())
    sorted_vals.sort(reverse=True)
    N = len(data)
    P_benford = 0
    for d, val in zip(np.arange(9) + 1, sorted_vals):
        P_d = math.log10((d + 1) / d)
        p_d = val / N
        P_benford += abs(P_d - p_d)
    plugin.P_BENFORD = 1 - P_benford / 2  # type: ignore


def delete_under_line_p_and_above_f(x, x_next, y, y_next, p, p_next, y_n, n):
    S = 0
    # compute triangle between points (x,y) (x,y_next) and (x_next,y_next)
    a = y - y_next
    b = x_next - x
    S += a * b / 2

    # compute rectangle between (x_next,y), (x_next,y_next), (x_n,y) and (x_n,y_next)
    S += (y - y_next) * (n - x_next)

    # compute triangle between points (x,p) (x,p_next) and (x_next,p_next)
    a = abs(p - p_next)
    b = x_next - x
    S += a * b / 2

    # compute rectangle between (x,p_next), (x_next,p_next), (x,y_n) and (x_next,y_n)
    S += (x_next - x) * (p_next - y_n)

    return S


def delete_above_line_p_and_under_f(x, x_next, y, y_next, p, p_next, y_n, n):
    S = 0
    # compute triangle between points (x,y) (x,y_next) and (x_next,y_next)
    a = abs(y - y_next)
    b = x_next - x
    S += a * b / 2

    # compute rectangle between (x,y_next), (x_next,y_next), (x,y_n) and (x_next,y_n)
    S += (x_next - x) * (y_next - y_n)

    # compute triangle between points (x,p) (x,p_next) and (x_next,p_next)
    a = abs(p - p_next)
    b = x_next - x
    S += a * b / 2

    # compute rectangle between (x_next,p), (x_next,p_next), (x_n,p) and (x_n,p_next)
    S += (p - p_next) * (n - x_next)

    return S


def find_intersection(i, y, y_next, y_1, y_n, n):
    I_1 = (y_n - n * y_1 + (i + 1) * (n - 1) * y - i * (n - 1) * y_next) / (
        (y_n - y_1) - (n - 1) * (y_next - y)
    )
    I_2 = ((y_n - y_1) * I_1 - y_n + n * y_1) / (n - 1)
    return I_1, I_2


def get_area_of_value_distribution(hist_data: dict, plugin: TimeSeriesPlugin):
    """_summary_

    Args:
        hist_data (dict): _description_
        plugin (TimeSeriesPlugin): _description_
    """
    sorted_vals = list(hist_data.values())
    sorted_vals.sort(reverse=True)
    sorted_vals = np.array(sorted_vals)

    y_1 = sorted_vals[0]
    y_n = sorted_vals[-1]
    n = len(sorted_vals)
    i_s = np.arange(n) + 1

    p_line = [y_1]  # p_1 = y_1
    for i in i_s:
        if i == 1 or i == n:
            continue
        p_i = ((i - 1) * y_n + (n - i) * y_1) / (n - 1)
        p_line.append(p_i)
    p_line.append(y_n)  # p_n = y_n

    S = (i_s[-1] - i_s[0]) * (y_1 - y_n)
    S_all = S

    for i, i_next, y, y_next, p, p_next in zip(
        i_s, i_s[1:], sorted_vals, sorted_vals[1:], p_line, p_line[1:]
    ):
        if y >= p and y_next >= p_next:
            S_d = delete_under_line_p_and_above_f(
                i, i_next, y, y_next, p, p_next, y_n, n
            )
            S -= S_d
        elif y <= p and y_next <= p_next:
            S_d = delete_above_line_p_and_under_f(
                i, i_next, y, y_next, p, p_next, y_n, n
            )
            S -= S_d
        elif y >= p and y_next <= p_next:
            I_1, I_2 = find_intersection(i, y, y_next, y_1, y_n, n)
            # delete under line p to I and delete above f(x) = y to I
            S_d = delete_under_line_p_and_above_f(i, I_1, y, I_2, p, I_2, y_n, n)
            S -= S_d
            # delete above line p from I and delete under f(x) = y from I
            S_d = delete_above_line_p_and_under_f(
                I_1, i_next, I_2, y_next, I_2, p_next, y_n, n
            )
            S -= S_d
        else:
            I_1, I_2 = find_intersection(i, y, y_next, y_1, y_n, n)
            # delete above line p to I and delete under f(x) = y to I
            S_d = delete_above_line_p_and_under_f(i, I_1, y, I_2, p, I_2, y_n, n)
            S -= S_d
            # delete under line p from I and delete above f(x) = y from I
            S_d = delete_under_line_p_and_above_f(
                I_1, i + 1, I_2, y_next, I_2, p_next, y_n, n
            )
            S -= S_d
    plugin.AREA_VALUES_DISTRIBUTION = S / (S_all / 2)


def get_cnt_distribution(aggregated_ts: np.ndarray, plugin: TimeSeriesPlugin):
    if aggregated_ts.size == 0:
        return
    mean_agg_ts = aggregated_ts.mean()
    tmp = 0
    for d in aggregated_ts:
        tmp += abs(mean_agg_ts - d)
    scale = aggregated_ts.max() - aggregated_ts.min()
    if scale == 0:
        plugin.CNT_DISTRIBUTION = (tmp / aggregated_ts.size)
    else:
        plugin.CNT_DISTRIBUTION = (tmp / aggregated_ts.size) / (scale / 2)

# time features
def get_time_distribution(time: np.ndarray, plugin: TimeSeriesPlugin):
    """Time distribution compute value between 0 and 1, where
    0.5 is ideal time distribution of time series, that means
    datapoints are in time distributed evenly. If value is
    between 0 and 0.5 it means datapoints are more often in
    beginning of time series.

    It can be computed without creating time series on
    exporter. It can compute norm_t_tmp by add normed time
    of each packet to one variable. Then when export of flow
    is ready it will use TIME_FIRST, TIME_LAST, PACKETS and
    PACKETS_REV, for compute metric.

    It cost (p+1) subtraction, p addition, 2 division and
    1 memory spaces (flow type).

    Args:
        time (np.ndarray): _description_
        plugin (TimeSeriesPlugin): _description_
    """
    p = len(time)
    if p < 2:
        return 0.5
    t_0 = time[0]  # TIME_FIRST from basic plugin
    t_n = time[-1]  # TIME_LAST from basic plugin
    norm_t_tmp = 0
    for t in time:
        norm_t_tmp += t - t_0
    norm_mi_t = norm_t_tmp / p
    d_t = t_n - t_0
    if d_t == 0:
        plugin.TIME_DISTRIBUTION = norm_mi_t
    else:
        plugin.TIME_DISTRIBUTION = norm_mi_t / d_t
    # plugin.TIME_DISTRIBUTION = (norm_t_tmp / p) / (t_n - t_0)


def get_mean_scaled_time(time: np.ndarray, plugin: TimeSeriesPlugin):
    """Compute comparable mean time as feature that try to describe, how the packets are distributed in the flow.

    Args:
        time (np.array): Time series times.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    # get number of seconds from first packet for each datapoint of time series (time differences from start)
    r_time = time - time[0]
    # get time of last packet
    plugin.DURATION = r_time[-1]
    plugin.MEAN_SCALED_TIME = statistics.mean(r_time)
    plugin.MEDIAN_SCALED_TIME = r_time[int(r_time.size/2)]
    plugin.Q1_SCALED_TIME = r_time[int(r_time.size/4)]
    plugin.Q3_SCALED_TIME = r_time[int( 3 * r_time.size / 4)]
    
        
def get_mean_difftimes(time: np.ndarray, plugin: TimeSeriesPlugin):
    """Function return mean of time differences between flow records.

    Args:
        time (np.array): Time series times.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
    """
    difftimes = []
    for i, j in zip(time, time[1:]):
        difftimes.append(j - i)
    if len(difftimes) == 0:
        return
    plugin.MEAN_DIFFTIMES = statistics.mean(difftimes)
    plugin.MEDIAN_DIFFTIMES = statistics.median(difftimes)
    plugin.MIN_DIFFTIMES = min(difftimes)
    plugin.MAX_DIFFTIMES = max(difftimes)
    plugin.MEAN_SCALED_DIFFTIMES = plugin.MEAN_DIFFTIMES / max(difftimes)


# spaces detection for transient detection
def mean_detection(
    flow_times: np.ndarray, spaces: list, sig_level: int, results_mean: float
):
    """Perform detection of significantly larger spaces between flows ussing mean.

    Args:
        flow_times (np.array): Time information about flows in time series.
        spaces (list): Spaces length in list (created by T[i+1] -T[i], where T is flow_times).
        sig_level (int): Significance level for mean detection.
        results_mean (float): Mean of all spaces.

    Returns:
        list: List of spaces that are significantly bigger then mean.
    """
    bigger_then_mean = []
    sig_spaces = []
    for i in range(len(spaces)):
        if spaces[i] > results_mean * (1 + sig_level):
            bigger_then_mean.append(flow_times[i])
            sig_spaces.append(spaces[i])
    return bigger_then_mean, sig_spaces


def standard_deviation_detection(
    flow_times: np.ndarray, spaces: list, sig_level: int, standard_deviation: float
):
    """Perform detection of significantly larger spaces between flows ussing standard deviation.

    Args:
        flow_times (np.array): Time information about flows in time series.
        spaces (list): Spaces length in list (created by T[i+1] -T[i], where T is flow_times).
        sig_level (int): Significance level for mean detection.
        standard_deviation (float): Standard deviation of all spaces.

    Returns:
        list: List of significantly bigger spaces by standard deviation.
    """
    bigger_then_std = []
    for i in range(len(spaces)):
        if spaces[i] > standard_deviation * (1 + sig_level):
            bigger_then_std.append(flow_times[i])
    return bigger_then_std


def perform_spaces_detection(
    flow_times: np.ndarray,
    space_min_length: float = 0.05,
    sig_space_threshold: float = 10,
):
    """Performing space detection by combination methods by mean and by standard deviation.

    Args:
        flow_times (np.array): Time information about flows in time series.
        space_min_length (float, optional): Percentage of spaces that can be accepted as significantly bigger. Defaults to 0.025 (2.5%).
        sig_space_threshold (float, optional): Threshold for test that evaluate if significantly bigger spaces are present. Defaults to 2.5.

    Returns:
        list: Significantly bigger spaces.
    """
    N = len(flow_times)
    if N <= 1:
        return []
    all_spaces = []
    for i in range(N - 1):
        all_spaces.append(abs(flow_times[i + 1] - flow_times[i]))
    all_spaces = np.array(all_spaces)
    # analyze spaces
    len_spaces = len(all_spaces)
    if len_spaces == 0:
        return []
    max_space = all_spaces.max()
    if max_space == 0:
        return []
    # if this is True, significance space isn't probably occured
    results_mean = all_spaces.mean()
    if max_space / results_mean < sig_space_threshold:
        return []

    if len_spaces == 0:
        return []
    standard_deviation = np.std(all_spaces)

    # set adaptive threshold for significant spaces
    if results_mean < 0.1:
        sig_level = 100
    elif results_mean < 0.5:
        sig_level = 30
    elif results_mean < 0.75:
        sig_level = 10
    elif results_mean < 1:
        sig_level = 5
    else:
        sig_level = 1

    sig_flow_times = flow_times
    sig_spaces = all_spaces
    # while percentage of significantly bigger spaces is more then threshold space_min_length
    while len(sig_flow_times) / N > space_min_length:
        m, m_spaces = mean_detection(
            sig_flow_times, sig_spaces, sig_level, results_mean  # type: ignore
        )
        s = standard_deviation_detection(
            sig_flow_times, sig_spaces, sig_level, standard_deviation  # type: ignore
        )
        sig_flow_times = []
        sig_spaces = []
        for i in range(len(m)):
            if m[i] in s:
                sig_flow_times.append(m[i])
                sig_spaces.append(m_spaces[i])
        sig_level += 1
    return sig_flow_times


# time series behavior features
def has_transient(
    data: np.ndarray,
    time: np.ndarray,
    plugin: TimeSeriesPlugin,
    spaces: list,
    TIME_THRESHOLD: float = 0.2,
    MEAN_THRESHOLD: float = 0.15,
    NUMBER_THRESHOLD: int = 3,
    FALSE_TRANSIENT_THRESHOLD: int = 5,
):
    """Function finds transient in time series and return True if found at least one.

    Args:
        data (np.array): Time series data.
        time (np.array): Time series times.
        plugin (TimeSeriesPLugin): Class of TimeSeries ipfixprobe plugin for save output data.
        spaces (list): List of significance spaces.
        TIME_THRESHOLD (float, optional): Threshold for transient time interval in secondes. It sets on which time interval transient must occures. Defaults to 0.2.
        MEAN_THRESHOLD (float, optional): Threshold for mean of transient compared with mean of data. Defaults to 0.2.
        LENGTH_THRESHOLD (float, optional): Threshold for length of transient compared to all time series. Defaults to 10.
        NUMBER_THRESHOLD (int, optional): Number of datapoints that transient consists to be considered as candidate on transient. Defaults to 3.
        FALSE_TRANSIENT_THRESHOLD (int, optional): Number of false transients that can occurs before finding of transient end. Defaults to 5.

    Returns:
        bool: If time series contains transient return True.
    """
    N = len(data)
    start = None
    transient = []
    false_transients = 0
    for d, t in zip(data, time):
        if start is None:
            start = t
        if t - start < TIME_THRESHOLD:
            transient.append(d)
        else:
            if len(transient) > NUMBER_THRESHOLD:
                transient = np.array(transient)
                spaces_threshold = (N / transient.size) - 1
                if spaces_threshold < 1:
                    spaces_threshold = 1
                if transient.max() - transient.min() - 1 < transient.mean():
                    # if difference of max and min of transient is smaller then mean, it isn't transient
                    false_transients += 1  # false transient
                elif transient.mean() > plugin.MEAN * (1 + MEAN_THRESHOLD):  # type: ignore
                    # else if mean_transient much bigger than mean_data
                    plugin.TRANSIENTS = True  # type: ignore
                    return
                elif N * 0.9 < transient.size:
                    # transient contains "every" datapoints of time series
                    plugin.TRANSIENTS = True  # type: ignore
                    return
                elif len(spaces) > spaces_threshold:
                    # there are many significant spaces in time series
                    plugin.TRANSIENTS = True  # type: ignore
                    return
                else:
                    false_transients += 1  # false transient
            else:
                false_transients += 1  # false transient
            if false_transients >= FALSE_TRANSIENT_THRESHOLD:
                plugin.TRANSIENTS = False  # type: ignore
                return
            transient = [d]  # type: ignore
            start = t
    if len(transient) > 3:
        transient = np.array(transient)
        spaces_threshold = (N / transient.size) - 1
        if spaces_threshold < 1:
            spaces_threshold = 1
        if transient.max() - transient.min() - 1 < transient.mean():
            plugin.TRANSIENTS = False  # type: ignore
        elif transient.mean() > plugin.MEAN * (1 + MEAN_THRESHOLD):  # type: ignore
            # else if mean_transient much bigger than mean_data
            plugin.TRANSIENTS = True  # type: ignore
        elif N * 0.9 < transient.size:
            # transient contains "every" datapoints of time series
            plugin.TRANSIENTS = True  # type: ignore
        elif len(spaces) > spaces_threshold:
            # there are many significant spaces in time series
            plugin.TRANSIENTS = True  # type: ignore
        else:
            plugin.TRANSIENTS = False  # type: ignore

def get_switching_metric(data: np.ndarray, plugin: TimeSeriesPlugin):
    cnt = 0
    tmp = None
    for d in data:
        if tmp is None:
            tmp = d
        elif tmp != d:
            cnt += 1
            tmp = d
    max_possible_switchs = (data.size - 1) / 2
    if max_possible_switchs == 0:
        plugin.SWITCHING_METRIC = 0
    else:    
        plugin.SWITCHING_METRIC = cnt / max_possible_switchs

def get_cnt_behavior(aggregated_ts: np.ndarray, plugin: TimeSeriesPlugin):
    if aggregated_ts.size == 0:
        return
    cnt_z = 0
    nz_aggregated_ts = []
    for d in aggregated_ts:
        if d == 0:
            cnt_z += 1
        else:
            nz_aggregated_ts.append(d)
    plugin.CNT_ZEROS = cnt_z / aggregated_ts.size
    plugin.BIGGEST_CNT_1_SEC = aggregated_ts.max()
    if len(nz_aggregated_ts) == 0:
        return
    nz_aggregated_ts = np.array(nz_aggregated_ts)
    mean_nz_agg_ts = nz_aggregated_ts.mean()
    tmp = 0
    for d in nz_aggregated_ts:
        tmp += abs(mean_nz_agg_ts - d)
    scale = nz_aggregated_ts.max() - nz_aggregated_ts.min()
    if scale == 0:
        plugin.CNT_NZ_DISTRIBUTION = tmp / nz_aggregated_ts.size
    else:
        plugin.CNT_NZ_DISTRIBUTION = (tmp / nz_aggregated_ts.size) / (scale / 2)
        

def has_clear_periodicity(
    data: np.ndarray,
    times: np.ndarray,
    hist_data: dict,
    plugin: TimeSeriesPlugin,
    THRESHOLD: float = 0.95,
    NUMBER_THRESHOLD: int = 3,
):
    """Find clear periodic behavior in time series, by using histogram.

    Args:
        data (np.array): Time series data.
        time (np.array): Time series times.
        plugin (TimeSeriesPlugin): Class TimeSeriesPlugin that contains records for save plugin export items.
        THRESHOLD (float, optional): Percentage of traffic that is clear periodic. Defaults to 0.95.
        NUMBER_THRESHOLD (int, optional): Number of datapoints that must at least occurs in time series for being tested for clear periodicity.
    """
    if len(data) < NUMBER_THRESHOLD:
        plugin.PERIODICITY = False  # type: ignore
        plugin.VAL = 0
        plugin.TIME = 0
        return
    sum_prob = 0
    val = None
    for h in hist_data:
        prob = hist_data[h] / len(data)
        if prob >= THRESHOLD:
            val = h
            break
        sum_prob += prob
        if 1 - sum_prob < THRESHOLD:
            plugin.PERIODICITY = False  # type: ignore
            plugin.VAL = 0
            plugin.TIME = 0
            return
    per_times = {}
    before_time = None
    for d, t in zip(data, times):
        if d == val:
            if before_time is None:
                before_time = t
            else:
                tmp_per_time = t - before_time
                if tmp_per_time not in per_times:
                    per_times[tmp_per_time] = 0
                per_times[tmp_per_time] += 1
    per_time = None
    per_time_counts = None
    for t in per_times:
        if per_time is None:
            per_time = t
            per_time_counts = per_times[t]
        else:
            if per_time_counts < per_times[t]:
                per_time = t
                per_time_counts = per_times[t]
    plugin.PERIODICITY = True  # type: ignore
    if val is not None:
        plugin.VAL = val
    if per_time is not None:
        plugin.TIME = per_time
    return


# aggregate one flow time series
def aggreagation_of_time_series(data: np.ndarray, time: np.ndarray, interval: int = 60):
    aggregated_time_series = []
    start_time = time[0] - (time[0] % interval)
    agg = 0
    for d, t in zip(data, time):
        if t < start_time + interval:
            agg += d
        else:
            aggregated_time_series.append(agg)
            start_time += interval
            while t > start_time + interval:
                start_time += interval
                aggregated_time_series.append(0)
            agg = d
    if agg > 0:
        aggregated_time_series.append(agg)
    return np.array(aggregated_time_series)


# normal distribution in aggregated time series
def is_normal_distribution_present(agg_ts: list, plugin: TimeSeriesPlugin):
    if len(agg_ts) >= 4:
        lilliefors_val, p_value = lilliefors(agg_ts)
        plugin.NORMAL_DISTRIBUTION = p_value  # type: ignore
    else:
        plugin.NORMAL_DISTRIBUTION = 0  # type: ignore


def get_dev_and_ports_from_packets(src_ip, src_port, dst_ip, dst_port, flows):
    direction = True
    if f"{src_ip}-{dst_ip}" in flows:
        dev = f"{src_ip}-{dst_ip}"
        if f"{src_port}-{dst_port}" in flows[dev]:
            ports = f"{src_port}-{dst_port}"
        elif f"{dst_port}-{src_port}" in flows[dev]:
            ports = f"{dst_port}-{src_port}"
        else:
            ports = f"{src_port}-{dst_port}"
    elif f"{dst_ip}-{src_ip}" in flows:
        direction = False
        dev = f"{dst_ip}-{src_ip}"
        if f"{src_port}-{dst_port}" in flows[dev]:
            ports = f"{src_port}-{dst_port}"
        elif f"{dst_port}-{src_port}" in flows[dev]:
            ports = f"{dst_port}-{src_port}"
        else:
            ports = f"{src_port}-{dst_port}"
    else:
        dev = f"{src_ip}-{dst_ip}"
        ports = f"{src_port}-{dst_port}"
    return dev, ports, direction

def scdf_test(
    power: np.array,
    sig_level: float = 0.1,
    per_level: float = 0.995,
):
    """Perform the SCDF (Scargles Cumulative Distribution Function) significant test.

    Args:
        power (list): List of power of LS periodogram.
        per_level (float, optional): Percent of power for SCDF. Defaults to 0.9.
        sig_level (float, optional): Percent of max power for SCDF. Defaults to 0.01.
        
    Returns:
        tuple: First value is if candidate on periodicity is accepted or denied, and seconde value is confidence.
    """
    s = power.max()
    if s == float("inf"):
        s = sys.float_info.max * sig_level
    else:
        s = s * sig_level
    return 1 - math.exp(-(s) / power.var())
    # if 1 - math.exp(-(s) / power.var()) < per_level:
    #     return False
    # return True



def compute_frequency_features(flowtime: np.ndarray, flowdata: np.ndarray, plugin: TimeSeriesPlugin):
    try:
        ls = LombScargle(flowtime, flowdata)
        # frequency, power = ls.autopower() # minimum_frequency=0, maximum_frequency=10)
        frequency = FREQUENCY
        power = ls.power(frequency)
    except:
        return
    power = power[power != -np.inf][power != np.inf]
    if len(power) == 0:
        return
    
    plugin.MAX_POWER = power.max()
    try:
        plugin.MAX_POWER_FREQ = frequency[np.asarray(power == plugin.MAX_POWER).nonzero()[0][0]]
        if math.isnan(plugin.MAX_POWER_FREQ):
            plugin.MAX_POWER_FREQ = DEFAULT_VALUE
    except:
        pass
    # 
    plugin.MIN_POWER = np.nanmin(power)
    try:
        plugin.MIN_POWER_FREQ = frequency[np.asarray(power == plugin.MIN_POWER).nonzero()[0][0]]
        if math.isnan(plugin.MIN_POWER_FREQ):
            plugin.MIN_POWER_FREQ = DEFAULT_VALUE
    except:
        pass
    plugin.POWER_MEAN = power.mean()
    plugin.POWER_STD = power.std()
    # np.round(power, 5)
    plugin.POWER_MODE = Counter((power*100000).astype(int)).most_common(1)[0][0] / 100000
    # _power = power[power >= 0]
    # if len(_power) > 0:
    #     plugin.POWER_MODE = np.bincount((np.round(_power, 5)*100000).astype(int)).argmax() / 100000
    # else:
    #     plugin.POWER_MODE = -(np.bincount((np.round(abs(power), 5)*100000).astype(int)).argmax() / 100000)
    # Spectral Energy: The total energy present at all frequencies in the periodogram
    try:
        plugin.SPECTRAL_ENERGY = power.sum()
        if math.isnan(plugin.SPECTRAL_ENERGY):
            plugin.SPECTRAL_ENERGY = DEFAULT_VALUE
    except:
        pass
    # Spectral Entropy: A measure of the randomness or disorfer in periodogram
    try:
        plugin.SPECTRAL_ENTROPY = -np.sum(power * np.log2(power))
        if math.isnan(plugin.SPECTRAL_ENTROPY):
            plugin.SPECTRAL_ENTROPY = DEFAULT_VALUE
    except:
        pass
    # Spectral Kurtosis (Flatness): A measure of the uniformity of the power spectrum.
    try:
        plugin.SPECTRAL_KURTOSIS = np.sum(np.power(power - np.mean(power), 4)) / np.power(np.std(power), 4)
        if math.isnan(plugin.SPECTRAL_KURTOSIS):
            plugin.SPECTRAL_KURTOSIS = DEFAULT_VALUE
    except:
        pass
    # Spectral Skewness: A measure of the peakedness or flatness of the power spectrum
    try:
        plugin.SPECTRAL_SKEWNESS = np.sum(np.power(power - np.mean(power), 3)) / np.power(np.std(power), 3)
        if math.isnan(plugin.SPECTRAL_SKEWNESS):
            plugin.SPECTRAL_SKEWNESS = DEFAULT_VALUE
    except:
        pass
    # Spectral Rolloff: The frequecny at which the power spectrum falls off significantly
    try:
        threshold = 0.85 * power.max()
        rolloff_idx = np.argmax(power > threshold)
        plugin.SPECTRAL_ROLLOFF = frequency[rolloff_idx]
        if math.isnan(plugin.SPECTRAL_ROLLOFF):
            plugin.SPECTRAL_ROLLOFF = DEFAULT_VALUE
    except:
        pass
    # Spectral Centroid: The average frequency of the power spectrum
    try:
        plugin.SPECTRAL_CENTROID = np.sum(frequency * power) / np.sum(power)
        if math.isnan(plugin.SPECTRAL_CENTROID):
            plugin.SPECTRAL_CENTROID = DEFAULT_VALUE
    except:
        pass
    # Spectral Spread: The difference between the highest and lowest frequencies in the power spectrum
    try:
        plugin.SPECTRAL_SPREAD = np.sqrt(np.sum((frequency - plugin.SPECTRAL_CENTROID)**2 * power) / np.sum(power))
        if math.isnan(plugin.SPECTRAL_SPREAD):
            plugin.SPECTRAL_SPREAD = DEFAULT_VALUE
    except:
        pass
    # Spectral Slope: The slope of trend of the power spectrum over a given frequency range
    try:
        plugin.SPECTRAL_SLOPE = np.polyfit(np.log(frequency), np.log(power), deg=1)[0]
        if math.isnan(plugin.SPECTRAL_SLOPE):
            plugin.SPECTRAL_SLOPE = DEFAULT_VALUE
    except:
        pass
    # Spectral Crest: the ratio of the peak spectral magnitude to the average spectral magnitude
    try:
        plugin.SPECTRAL_CREST = np.max(power) / np.mean(power)
        if math.isnan(plugin.SPECTRAL_CREST):
            plugin.SPECTRAL_CREST = DEFAULT_VALUE
    except:
        pass
    # Spectral Flux: the rate of change of the spectral energy over time
    try:
        plugin.SPECTRAL_FLUX = np.sum(np.abs(power[1:] - power[:-1]))
        if math.isnan(plugin.SPECTRAL_FLUX):
            plugin.SPECTRAL_FLUX = DEFAULT_VALUE
    except:
        pass
    # Spectral Bandwidth: the difference between the upper and lower frequencies at which the spectral energy is half of its maximum value
    try:
        plugin.SPECTRAL_BANDWIDTH = frequency[np.argmax(power)] - frequency[np.argmin(power)]
        if math.isnan(plugin.SPECTRAL_BANDWIDTH):
            plugin.SPECTRAL_BANDWIDTH = DEFAULT_VALUE
    except:
        pass
    try:
        plugin.PERIODICITY_SCDF = scdf_test(abs(power), sig_level=0.001, per_level=0.9995)
    except:
        pass
            
    

# perform computing plugin metrics
def compute_plugin_metrics(bytes, time, ip1, ip2, port1, port2):
    if len(bytes) == 0:
        return None
    flow_data = np.array(bytes)
    flow_data += 60
    flow_time = np.array(time)
    # get histogram of datapoints
    hist_data = {}
    for d in flow_data:
        if d not in hist_data:
            hist_data[d] = 0
        hist_data[d] += 1
    # create extended flow
    extended_flow = TimeSeriesPlugin(ip1, ip2, port1, port2)
    # Get duration
    extended_flow.DURATION = flow_time[-1] - flow_time[0]
    # fill time series plugin
    get_basic_stats(flow_data, extended_flow)
    get_skewness(flow_data, hist_data, extended_flow)
    get_kurtosis(flow_data, extended_flow)
    get_entropy(flow_data, extended_flow)
    perform_getting_hurst_exponent(flow_data, extended_flow)
    is_benford_law_present(flow_data, hist_data, extended_flow)
    benford_law_probability(flow_data, hist_data, extended_flow)
    get_area_of_value_distribution(hist_data, extended_flow)
    agg_ts = aggreagation_of_time_series(flow_data, flow_time)
    is_normal_distribution_present(agg_ts, extended_flow)
    get_cnt_distribution(agg_ts, extended_flow)
    get_time_distribution(flow_time, extended_flow)
    get_mean_scaled_time(flow_time, extended_flow)
    get_mean_difftimes(flow_time, extended_flow)
    spaces = perform_spaces_detection(
        flow_time,
        space_min_length=0.05,
        sig_space_threshold=10,
    )
    if len(spaces) > 0:
        extended_flow.SIG_SPACES = True  # type: ignore
    get_switching_metric(flow_data, extended_flow)
    has_transient(flow_data, flow_time, extended_flow, spaces)  # type: ignore
    get_cnt_behavior(agg_ts, extended_flow)
    has_clear_periodicity(flow_data, flow_time, hist_data, extended_flow)
    # fill basic plugin info
    extended_flow.PACKETS = len(bytes)  # type: ignore
    extended_flow.BYTES = flow_data.sum()
    extended_flow.TIME_FIRST = flow_time[0]
    extended_flow.TIME_LAST = flow_time[-1]
    compute_frequency_features(flow_time, flow_data, extended_flow)
    return extended_flow


def create_new_flow_ts(length, time):
    return {
        "bytes": [length],
        "time": [time],
        "direction_0": 0,
        "direction_1": 1,
        # "bytes_0": [],
        # "time_0": [],
        # "bytes_1": [length],
        # "time_1": [time],
        "npackets": 1,
        "npackets_rev": 0,
        "nbytes": length,
        "nbytes_rev": 0,
        "first": True,
    }

def save_timeseries(arg):
    cnt_flows = 0
    cnt_packets = 0
    cnt_except = 0
    with open(arg.file, "w") as wf:
        writer = csv.writer(wf, delimiter=";")
        print("Write header:", end=" ")
        writer.writerow(["SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT", "bytes", "time"])
        print("Done")
        print("Creating extended flows from packets:")
        print(
            f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}     Except: {cnt_except}",
            end="",
        )
        flows = {}
        for _t, buf in ppcap.Reader(filename=arg.pcap):
            eth = ethernet.Ethernet(buf)
            if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
                try:
                    src_ip = eth[ip.IP].src_s
                    src_port = eth[tcp.TCP].sport
                    dst_ip = eth[ip.IP].dst_s
                    dst_port = eth[tcp.TCP].dport
                    length = len(eth)
                except:
                    cnt_except += 1
                    continue
                cnt_packets += 1
                dev, ports = get_dev_and_ports_from_packets(
                    src_ip, src_port, dst_ip, dst_port, flows
                )
                t = _t / 1000000000
                if dev in flows:
                    if ports in flows[dev]:
                        if len(flows[dev][ports]["time"]) != 0 and (
                            (flows[dev][ports]["time"][0] + ACTIVE_TIMEOUT < t)
                            or (
                                len(flows[dev][ports]["time"]) > 0
                                and t - flows[dev][ports]["time"][-1]
                                >= INACTIVE_TIMEOUT
                            )
                        ):
                            if len(flows[dev][ports]["bytes"]) == 0:
                                continue
                            writer.writerow(
                                [
                                    src_ip,
                                    src_port,
                                    dst_ip,
                                    dst_port,
                                    flows[dev][ports]["bytes"],
                                    flows[dev][ports]["time"],
                                ]
                            )
                            cnt_flows += 1
                            flows[dev][ports]["bytes"].clear()
                            flows[dev][ports]["time"].clear()
                        flows[dev][ports]["bytes"].append(length)
                        flows[dev][ports]["time"].append(t)
                    else:
                        flows[dev][ports] = create_new_flow_ts(length, t)
                else:
                    flows[dev] = {ports: create_new_flow_ts(length, t)}
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}     Except: {cnt_except}",
                    end="",
                    flush=False,
                )
                # if cnt_packets % 1000000 == 0:
                #     for dev in flows:
                #         for ports in flows[dev]:
                #             if (
                #                 len(flows[dev][ports]["bytes"]) == 0
                #                 or t - flows[dev][ports]["time"][-1] - 5
                #                 < INACTIVE_TIMEOUT
                #             ):
                #                 continue
                #             writer.writerow(
                #                 [
                #                     dev.split("-")[0],
                #                     ports.split("-")[0],
                #                     dev.split("-")[1],
                #                     ports.split("-")[1],
                #                     flows[dev][ports]["bytes"],
                #                     flows[dev][ports]["time"],
                #                 ]
                #             )
                #             cnt_flows += 1
                #             flows[dev][ports]["bytes"].clear()
                #             flows[dev][ports]["time"].clear()
                #             print(
                #                 f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}     Except: {cnt_except}",
                #                 end="",
                #                 flush=False,
                #             )

        for dev in flows:
            for ports in flows[dev]:
                if len(flows[dev][ports]["bytes"]) == 0:
                    continue
                writer.writerow(
                    [
                        dev.split("-")[0],
                        ports.split("-")[0],
                        dev.split("-")[1],
                        ports.split("-")[1],
                        flows[dev][ports]["bytes"],
                        flows[dev][ports]["time"],
                    ]
                )
                cnt_flows += 1
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}     Except: {cnt_except}",
                    end="",
                    flush=False,
                )

        print("")
    return cnt_flows, cnt_packets


def timeseries_plugin(arg):
    cnt_flows = 0
    cnt_packets = 0
    with open(arg.flows, "w") as w:
        writer = csv.writer(w)
        print("Write header:", end=" ")
        writer.writerow(HEADER)
        print("Done")
        print("Creating extended flows from packets:")
        print(
            f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
            end="",
        )
        flows = {}

        for _t, buf in ppcap.Reader(filename=arg.pcap):
            eth = ethernet.Ethernet(buf)
            if eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None:
                try:
                    src_ip = eth[ip.IP].src_s
                    src_port = eth[tcp.TCP].sport
                    dst_ip = eth[ip.IP].dst_s
                    dst_port = eth[tcp.TCP].dport
                    length = len(eth)
                except:
                    continue
                cnt_packets += 1
                dev, ports = get_dev_and_ports_from_packets(
                    src_ip, src_port, dst_ip, dst_port, flows
                )
                t = _t / 1000000000
                if dev in flows:
                    if ports in flows[dev]:
                        if (flows[dev][ports]["time"][0] + ACTIVE_TIMEOUT < t) or (
                            len(flows[dev][ports]["time"]) > 0
                            and t - flows[dev][ports]["time"][-1] >= INACTIVE_TIMEOUT
                        ):
                            extended_flow = compute_plugin_metrics(
                                flows[dev][ports]["bytes"],
                                flows[dev][ports]["time"],
                                dev.split("-")[0],
                                dev.split("-")[1],
                                ports.split("-")[0],
                                ports.split("-")[1],
                            )
                            if extended_flow is None:
                                continue
                            # export extended flow
                            writer.writerow(extended_flow.export())
                            # print
                            cnt_flows += 1
                            # clear data
                            flows[dev][ports]["bytes"].clear()
                            flows[dev][ports]["time"].clear()
                        flows[dev][ports]["bytes"].append(length)
                        flows[dev][ports]["time"].append(t)
                    else:
                        flows[dev][ports] = create_new_flow_ts(length, t)
                else:
                    flows[dev] = {ports: create_new_flow_ts(length, t)}
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
                    end="",
                    flush=True,
                )
        for dev in flows:
            for ports in flows[dev]:
                extended_flow = compute_plugin_metrics(
                    flows[dev][ports]["bytes"],
                    flows[dev][ports]["time"],
                    dev.split("-")[0],
                    dev.split("-")[1],
                    ports.split("-")[0],
                    ports.split("-")[1],
                )
                if extended_flow is None:
                    continue
                # export extended flow
                writer.writerow(extended_flow.export())
                # print
                cnt_flows += 1
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
                    end="",
                    flush=False,
                )
    return cnt_flows, cnt_packets


def save_all_to_file(flows, cnt_flows, cnt_packets, writer, t=None):
    for dev in flows:
        for ports in flows[dev]:
            if len(flows[dev][ports]["bytes"]) == 0 or (
                t is not None
                and t - flows[dev][ports]["time"][-1] - 5 < INACTIVE_TIMEOUT
            ):
                continue
            writer.writerow(
                [
                    dev.split("-")[0],
                    ports.split("-")[0],
                    dev.split("-")[1],
                    ports.split("-")[1],
                    flows[dev][ports]["bytes"],
                    flows[dev][ports]["time"],
                ]
            )
            cnt_flows += 1
            flows[dev][ports]["bytes"].clear()
            flows[dev][ports]["time"].clear()
            print(
                f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
                end="",
                flush=False,
            )
    return flows, cnt_flows


def save_timeseries_csv(arg):
    cnt_flows = 0
    cnt_packets = 0
    with open(arg.file, "w") as wf:
        writer = csv.writer(wf, delimiter=";")
        print("Write header:", end=" ")
        writer.writerow(["SRC_IP", "SRC_PORT", "DST_IP", "DST_PORT", "bytes", "time"])
        print("Done")
        print("Creating extended flows from packets:")
        print(
            f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
            end="",
        )
        flows = {}
        with open(arg.csv, "r") as rf:
            reader = csv.reader(rf, delimiter=" ")
            for row in reader:
                # row is in format ['1662638393.520198', 'IP', '192.168.1.104.8085', '>', '192.168.1.245.45820:', 'tcp', '78']
                if len(row) < 6:
                    # print(row)
                    continue
                t = float(row[0])
                if row[5] == "tcp":
                    length = int(row[6])
                    dst_port = row[4].split(".")[-1]
                    dst_ip = row[4][: -len(dst_port) + 1]
                elif row[5] == "UDP,":
                    length = int(row[7])
                    dst_port = row[4][:-1].split(".")[-1]
                    dst_ip = row[4][:-1][: -len(dst_port) + 1]
                else:
                    # print(row)
                    continue
                src_port = row[2].split(".")[-1]
                src_ip = row[2][: -len(src_port) + 1]
                cnt_packets += 1
                dev, ports, direction = get_dev_and_ports_from_packets(
                    src_ip, src_port, dst_ip, dst_port, flows
                )
                if dev in flows:
                    if ports in flows[dev]:
                        if len(flows[dev][ports]["time"]) != 0 and (
                            flows[dev][ports]["time"][0] + ACTIVE_TIMEOUT < t
                            or t - flows[dev][ports]["time"][-1] >= INACTIVE_TIMEOUT
                        ):
                            if len(flows[dev][ports]["bytes"]) == 0:
                                continue
                            writer.writerow(
                                [
                                    src_ip,
                                    src_port,
                                    dst_ip,
                                    dst_port,
                                    flows[dev][ports]["bytes"],
                                    flows[dev][ports]["time"],
                                ]
                            )
                            cnt_flows += 1
                            flows[dev][ports]["bytes"].clear()
                            flows[dev][ports]["time"].clear()
                        flows[dev][ports]["bytes"].append(length)
                        flows[dev][ports]["time"].append(t)
                    else:
                        flows[dev][ports] = create_new_flow_ts(length, t)
                else:
                    flows[dev] = {ports: create_new_flow_ts(length, t)}
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
                    end="",
                    flush=False,
                )
                if cnt_packets % 1000000 == 0:
                    flows, cnt_flows = save_all_to_file(
                        flows, cnt_flows, cnt_packets, writer, t
                    )
        flows, cnt_flows = save_all_to_file(flows, cnt_flows, cnt_packets, writer)
        print("")
    return cnt_flows, cnt_packets


def timeseries_plugin_csv(arg):
    cnt_flows = 0
    cnt_packets = 0
    with open(arg.flows, "w") as w:
        writer = csv.writer(w)
        print("Write header:", end=" ")
        writer.writerow(HEADER)
        print("Done")
        print("Creating extended flows from packets:")
        print(
            f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
            end="",
        )
        flows = {}
        with open(arg.csv, "r") as rf:
            reader = csv.reader(rf, delimiter=" ")
            for row in reader:
                if len(row) < 6:
                    # print(row)
                    continue
                try:
                    t = float(row[0])
                except:
                    continue
                if row[5] == "tcp":
                    length = int(row[6])
                    dst_port = row[4][:-1].split(".")[-1]
                    dst_ip = row[4][: -(len(dst_port) + 1)]
                elif row[5] == "UDP,":
                    length = int(row[7])
                    dst_port = row[4][:-1].split(".")[-1]
                    dst_ip = row[4][:-1][: -(len(dst_port) + 1)]
                else:
                    # print(row)
                    continue
                src_port = row[2].split(".")[-1]
                src_ip = row[2][: -(len(src_port) + 1)]
                cnt_packets += 1
                dev, ports, direction = get_dev_and_ports_from_packets(
                    src_ip, src_port, dst_ip, dst_port, flows
                )
                if dev in flows:
                    if ports in flows[dev]:
                        if (flows[dev][ports]["time"][0] + ACTIVE_TIMEOUT < t) or (
                            len(flows[dev][ports]["time"]) > 0
                            and t - flows[dev][ports]["time"][-1] >= INACTIVE_TIMEOUT
                        ):
                            if len(flows[dev][ports]["bytes"]) <= arg.I:
                                continue
                            if flows[dev][ports]["first"] is True:
                                tmp_i = arg.H
                            else:
                                tmp_i = 0
                            extended_flow = compute_plugin_metrics(
                                flows[dev][ports]["bytes"][tmp_i:],
                                flows[dev][ports]["time"][tmp_i:],
                                dev.split("-")[0],
                                dev.split("-")[1],
                                ports.split("-")[0],
                                ports.split("-")[1],
                            )
                            if extended_flow is None:
                                continue
                            # extended_flow_0 = compute_plugin_metrics(
                            #     flows[dev][ports]["bytes_0"][tmp_i:],
                            #     flows[dev][ports]["time_0"][tmp_i:],
                            #     dev.split("-")[0],
                            #     dev.split("-")[1],
                            #     ports.split("-")[0],
                            #     ports.split("-")[1],
                            # )
                            # if extended_flow_0 is not None:
                            #     extended_flow.extend_with_0_direction(extended_flow_0)
                            
                            # extended_flow_1 = compute_plugin_metrics(
                            #     flows[dev][ports]["bytes_1"][tmp_i:],
                            #     flows[dev][ports]["time_1"][tmp_i:],
                            #     dev.split("-")[0],
                            #     dev.split("-")[1],
                            #     ports.split("-")[0],
                            #     ports.split("-")[1],
                            # )
                            # if extended_flow_1 is not None:
                            #     extended_flow.extend_with_1_direction(extended_flow_1)
                            
                            extended_flow.DIRECTIONS = (flows[dev][ports]["direction_1"]) / (flows[dev][ports]["direction_1"] + flows[dev][ports]["direction_0"]) 
                            extended_flow.PACKETS = flows[dev][ports]["npackets"]
                            extended_flow.PACKETS_REV = flows[dev][ports]["npackets_rev"]
                            extended_flow.BYTES = flows[dev][ports]["nbytes"]
                            extended_flow.BYTES_REV = flows[dev][ports]["nbytes_rev"]
                            # export extended flow
                            writer.writerow(extended_flow.export())
                            # print
                            cnt_flows += 1
                            # clear data
                            flows[dev][ports]["bytes"].clear()
                            flows[dev][ports]["time"].clear()
                            # flows[dev][ports]["bytes_0"].clear()
                            # flows[dev][ports]["time_0"].clear()
                            # flows[dev][ports]["bytes_1"].clear()
                            # flows[dev][ports]["time_1"].clear()
                            flows[dev][ports]["first"] = False
                            flows[dev][ports]["npackets"] = 0
                            flows[dev][ports]["nbytes"] = 0
                            flows[dev][ports]["direction_1"] = 0
                            flows[dev][ports]["npackets_rev"] = 0
                            flows[dev][ports]["nbytes_rev"] = 0
                            flows[dev][ports]["direction_0"] = 0    
                        flows[dev][ports]["bytes"].append(length)
                        flows[dev][ports]["time"].append(t)
                        if direction is True:
                            flows[dev][ports]["npackets"] += 1
                            flows[dev][ports]["nbytes"] += length
                            flows[dev][ports]["direction_1"] += 1
                            # flows[dev][ports]["bytes_1"].append(length)
                            # flows[dev][ports]["time_1"].append(t)    
                        else:
                            flows[dev][ports]["npackets_rev"] += 1
                            flows[dev][ports]["nbytes_rev"] += length
                            flows[dev][ports]["direction_0"] += 1  
                            # flows[dev][ports]["bytes_0"].append(length)
                            # flows[dev][ports]["time_0"].append(t)    
                    else:
                        flows[dev][ports] = create_new_flow_ts(length, t)
                else:
                    flows[dev] = {ports: create_new_flow_ts(length, t)}
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
                    end="",
                    flush=True,
                )
        for dev in flows:
            for ports in flows[dev]:
                if len(flows[dev][ports]["bytes"]) <= arg.I:
                    continue
                if flows[dev][ports]["first"] is True:
                    tmp_i = arg.H
                else:
                    tmp_i = 0
                extended_flow = compute_plugin_metrics(
                    flows[dev][ports]["bytes"][tmp_i:],
                    flows[dev][ports]["time"][tmp_i:],
                    dev.split("-")[0],
                    dev.split("-")[1],
                    ports.split("-")[0],
                    ports.split("-")[1],
                )
                if extended_flow is None:
                    continue
                # extended_flow_0 = compute_plugin_metrics(
                #     flows[dev][ports]["bytes_0"][tmp_i:],
                #     flows[dev][ports]["time_0"][tmp_i:],
                #     dev.split("-")[0],
                #     dev.split("-")[1],
                #     ports.split("-")[0],
                #     ports.split("-")[1],
                # )
                # if extended_flow_0 is not None:
                #     extended_flow.extend_with_0_direction(extended_flow_0)
                
                # extended_flow_1 = compute_plugin_metrics(
                #     flows[dev][ports]["bytes_1"][tmp_i:],
                #     flows[dev][ports]["time_1"][tmp_i:],
                #     dev.split("-")[0],
                #     dev.split("-")[1],
                #     ports.split("-")[0],
                #     ports.split("-")[1],
                # )
                # if extended_flow_1 is not None:
                #     extended_flow.extend_with_1_direction(extended_flow_1)
                            
                extended_flow.DIRECTIONS = (flows[dev][ports]["direction_1"]) / (flows[dev][ports]["direction_1"] + flows[dev][ports]["direction_0"]) 
                extended_flow.PACKETS = flows[dev][ports]["npackets"]
                extended_flow.PACKETS_REV = flows[dev][ports]["npackets_rev"]
                extended_flow.BYTES = flows[dev][ports]["nbytes"]
                extended_flow.BYTES_REV = flows[dev][ports]["nbytes_rev"]
                # export extended flow
                writer.writerow(extended_flow.export())
                # print
                cnt_flows += 1
                print(
                    f"\r      Number of exported flows: {cnt_flows}      Number of parsed packets: {cnt_packets}",
                    end="",
                    flush=False,
                )
    return cnt_flows, cnt_packets


def timeseries_plugin_timeseries_csv(arg):
    cnt_flows = 0
    with open(arg.flows, "w") as w:
        writer = csv.writer(w)
        print("Write header:", end=" ")
        writer.writerow(HEADER)
        print("Done")
        print("Creating extended flows from single flow time series:")
        print(f"\r      Number of exported flows: {cnt_flows}", end="")
        with open(arg.timeseries_csv, "r") as rf:
            reader = csv.reader(rf, delimiter=";")
            for row in reader:
                if row[0] == "SRC_IP":
                    continue
                # row is in format SRC_IP;SRC_PORT;DST_IP;DST_PORT;bytes;time
                extended_flow = compute_plugin_metrics(
                    json.loads(row[4]),
                    json.loads(row[5]),
                    row[0],
                    row[1],
                    row[2],
                    row[3],
                )
                if extended_flow is None:
                    continue
                # export extended flow
                writer.writerow(extended_flow.export())
                # print
                cnt_flows += 1
                print(
                    f"\r      Number of exported flows: {cnt_flows}", end="", flush=True
                )
    return cnt_flows, 0


def parse_arguments():
    """Parse program arguments using the argparse module.

    Returns:
        Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="""Module for add information about Network Dependency for each flow. Supported inputs of flows are NEMEA IFC, flow CSV file.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "-c",
        "--csv",
        help="Specification of csv file with IP header info from tcpdump command (tcpdump -r  example.pcap -N -n -q -tt > example.csv).",
        type=str,
        metavar="NAME.pcap",
        default="",
    )
    parser.add_argument(
        "-t",
        "--timeseries_csv",
        help="Specification of csv file with single flow time series.",
        type=str,
        metavar="NAME.pcap",
        default="",
    )
    parser.add_argument(
        "-p",
        "--pcap",
        help="Specification of pcap file for pcap type of input.",
        type=str,
        metavar="NAME.pcap",
        default="",
    )
    parser.add_argument(
        "-f",
        "--flows",
        help="Specification of CSV file for flows with TimeSeries plugin.",
        type=str,
        metavar="NAME.csv",
    )
    parser.add_argument(
        "--file",
        help="Specification of CSV file for packet time series. Default is disabled.",
        type=str,
        metavar="NAME.csv",
        default="",
    )
    parser.add_argument(
        "-H",
        help="Remove first x packets from flow (do not add into analysis). Default is disabled.",
        type=int,
        metavar="NUMBER",
        default=0,
    )
    parser.add_argument(
        "-I",
        help="Ignore flow with x or less packets. Default is disabled.",
        type=int,
        metavar="NUMBER",
        default=0,
    )
    arg = parser.parse_args()
    return arg


def main():
    """Main function of the module."""
    arg = parse_arguments()

    print("Loadind pcap:", end=" ")

    tic = time.perf_counter()
    print("Open write file")
    if arg.pcap != "":
        if arg.file != "":
            cnt_flows, cnt_packets = save_timeseries(arg)
        else:
            cnt_flows, cnt_packets = timeseries_plugin(arg)
    elif arg.csv != "":
        if arg.file != "":
            cnt_flows, cnt_packets = save_timeseries_csv(arg)
        else:
            cnt_flows, cnt_packets = timeseries_plugin_csv(arg)
    elif arg.timeseries_csv != "":
        if arg.file != "":
            print(
                "WARNING: Creating single flow timeseries file from another single flow timeseries file is stupid. Use cp command."
            )
            sys.exit(1)
        else:
            cnt_flows, cnt_packets = timeseries_plugin_timeseries_csv(arg)
    else:
        print("ERROR: Not input selected!")
        sys.exit(1)
    toc = time.perf_counter()
    print("")
    if cnt_flows != 0:
        print(
            f"Completed in {toc - tic:0.4f} seconds, thats is {(toc - tic)/cnt_flows:0.4f} seconds on one flow, that is {1/((toc - tic)/cnt_flows)} flow per second."
        )
    if cnt_packets != 0:
        print(
            f"It parse one packet at {(toc - tic)/cnt_packets:0.4f} seconds, that is {1/((toc - tic)/cnt_packets)} packets per second."
        )
    print("All exported")


if __name__ == "__main__":
    main()
