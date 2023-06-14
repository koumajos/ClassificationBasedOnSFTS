#!/bin/bash
# Test of time series plugin for ipfixprobe.
#  - use python modules: add_dependency and ipfixprobe_plugin_test 
#
# author: Josef Koumar
# e-mail: koumajos@fit.cvut.cz, koumar@cesnet.cz
#
############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Usage:"
   echo "  Add description of the script functions here."
   echo
   echo "  Syntax: scriptTemplate [-h | -r ]"
   echo "  options:"
   echo "  -h     Print this Help."
   echo "  -r     Path to PCAP file."
   echo "  -t     Path to single flow time series."
   echo "  -p     Path to folder where ipfix_plugin_test.py is saved."
   echo "  -f     If want only export single flow time series choose csv file here."
   echo "  -P     Path to csv file with registered ports."
   echo "  -H     Set int vlaue, that will remove first x packets from flow."
   echo "  -I     Set int vlaue, that will ignore flows with equal or less packets to set number."
   echo
}

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

############################################################
############################################################
# Main program                                             #
############################################################
############################################################
############################################################
# Process the input options. Add options as needed.        #
############################################################
# Set variables
PCAP="NaN"
IPFIX_PLUGIN_PATH="."
PORTS_PATH="Ports.csv"
FLOW_FILE="False"
TIMESERIES_FILE="NaN"
H="0"
I="0"
# Get the options
while getopts ":hr:p:fP:t:H:I:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      r) # enter path to pcap file
         PCAP=$OPTARG;;
      p) # enter path to folder where ipfix_plugin_test.py is saved
         IPFIX_PLUGIN_PATH=$OPTARG;;
      f)
         FLOW_FILE="True";;
      t)
         TIMESERIES_FILE=$OPTARG;;
      P) # enter path to file with registered ports
         PORTS_PATH=$OPTARG;;
      H) 
         H=$OPTARG;;
      I) 
         I=$OPTARG;;
      \?) # Invalid option
         echo "Load arguments"
         echo "  Error: Invalid argument"
         echo " "
         Help
         exit;;
   esac
done
echo -e "${GREEN}Load arguments"
echo "  OK"


if [[ $TIMESERIES_FILE != "NaN" ]]; then
   echo "Test settings:"
   if [[  $FLOW_FILE == "True" ]]; then
      echo -e "  ${RED}ERROR: Creating single flow timeseries file from another single flow timeseries file is stupid. Use cp command."
      exit
   fi
   echo "  OK"
   echo "Time series plugin"
   echo "  Run command:"
   NAME=$(echo $TIMESERIES_FILE | tr "." "\n")
   for a in $NAME; do FIRST=$a; break; done
   TIME_SERIES_PLUGIN="$FIRST.pcap.timeseries_plugin.csv"
   echo "    $IPFIX_PLUGIN_PATH/feature_mining.py -t $TIMESERIES_FILE -f $TIME_SERIES_PLUGIN -H $H -I $I"
   echo -e "${NC}"
   $IPFIX_PLUGIN_PATH/feature_mining.py -t $TIMESERIES_FILE -f $TIME_SERIES_PLUGIN -H $H -I $I
   echo -e "${GREEN}Flows extended by time series plugin added to $TIME_SERIES_PLUGIN"
else
   echo "Test settings:"
   if [[ $PCAP == "NaN" ]]; then
      echo -e "  ${RED}ERROR: Enter path to PCAP file in argument -r"
      exit
   fi
   if [[ $PCAP != *.pcap ]]; then
      if [[ $PCAP != *.pcapng ]]; then
            echo -e "  ${RED}ERROR: PCAP file without suffix .pcap or .pcapng in -r"
            exit
      fi
   fi
   if [[ -f "$PCAP" ]]; then
      echo -e "  ${GREEN}OK: $PCAP exists."
   else 
      echo -e "  ${RED}ERROR: $PCAP does not exist"
      exit
   fi
   TIME_SERIES_PLUGIN="$PCAP.timeseries_plugin.csv"
   echo "Time series plugin"
   echo "  Run command:"
   if [[ -f "$PCAP.header_info.csv" ]]; then
      echo -e "${GREEN}    $PCAP.header_info.csv already exists... skipping"
   else
      echo "    tcpdump -r  $PCAP -N -n -q -tt > test_file.cvs"
      tcpdump -r  $PCAP -N -n -q -tt > "test_file.cvs"
      echo "    mv test_file.cvs $PCAP.header_info.csv"
      mv "test_file.cvs" "$PCAP.header_info.csv"
   fi
   if [[  $FLOW_FILE == "True" ]]; then
      echo "    $IPFIX_PLUGIN_PATH/feature_mining.py -c $PCAP.header_info.csv -f $TIME_SERIES_PLUGIN --file $PCAP.single_flow_timeseries.csv -H $H -I $I"
      echo -e "${NC}"
      $IPFIX_PLUGIN_PATH/feature_mining.py -c "$PCAP.header_info.csv" -f $TIME_SERIES_PLUGIN --file "$PCAP.single_flow_timeseries.csv" -H $H -I $I
      echo -e "${GREEN}Time series of single flows added to $PCAP.single_flow_timeseries.csv"
   else
      echo "    $IPFIX_PLUGIN_PATH/feature_mining.py -c $PCAP.header_info.csv -f $TIME_SERIES_PLUGIN -H $H -I $I"
      echo -e "${NC}"
      $IPFIX_PLUGIN_PATH/feature_mining.py -c "$PCAP.header_info.csv" -f $TIME_SERIES_PLUGIN -H $H -I $I
      echo -e "${GREEN}Flows extended by time series plugin added to $TIME_SERIES_PLUGIN"
   fi
fi
