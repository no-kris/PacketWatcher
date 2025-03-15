# Packet Watcher

## Overview
Packet Watcher is a web-based tool for analyzing and visualizing network traffic data from PCAP files. This tool helps users gain insights into network traffic patterns, protocol distributions, and potential anomalies within their captured network data.

## Features

 - PCAP File Analysis: Upload and process PCAP files

## Interactive Visualizations:

 - Protocol distribution pie chart
 - Top source and destination IP address charts
 - Detailed packet statistics table

## Technical Architecture

The application consists of three main components:

 - PacketProcessor: Handles reading and processing of PCAP files, extracting packet information
 - Dashboard: Creates visualizations using Plotly
 - Streamlit App: Provides the web interface