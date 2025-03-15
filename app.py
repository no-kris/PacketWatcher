import asyncio
import logging
import os
import tempfile
import streamlit as st
import pandas as pd

from dashboard import Dashboard
from process_packet import PacketProcessor


@st.cache_data
def get_processed_dataframe(_processor):
    """Return cached dataframe to avoid reprocessing"""
    return _processor.get_dataframe()


@st.cache_resource
def get_processor():
    """Create and cache a processor instance"""
    return PacketProcessor()


async def process_file(processor, file_path):
    """Process the file and return packet count"""
    return await processor.process_packets(file_path)


async def main():
    st.set_page_config(
        page_title="Packet Watcher",
        page_icon="🔍",
        layout="wide"
    )

    st.sidebar.title("Network Analysis Dashboard")

    with st.sidebar.expander("About", expanded=False):
        st.write("""
        This dashboard analyzes PCAP files to provide insights into network traffic patterns, 
        protocol distributions, and potential anomalies.
        """)

    processor = get_processor()

    if 'file_processed' not in st.session_state:
        st.session_state.file_processed = False

    uploaded_file = st.sidebar.file_uploader(
        "Choose a PCAP file", type=['pcap', 'pcapng'])

    st.title("Packet Watcher - Network Analysis")
    st.markdown(
        "Upload a PCAP file to analyze network traffic patterns and statistics.")

    if uploaded_file is not None and not st.session_state.file_processed:
        with st.spinner("Processing packet data... Feel free to leave and come back when finished."):
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                temp_path = tmp_file.name

            try:
                count = await process_file(processor, temp_path)
                st.session_state.file_processed = True
                st.session_state.last_file_name = uploaded_file.name
                st.success(f"Successfully processed {count} packets")

            except Exception as e:
                st.error(f"Error processing file: {str(e)}")

            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    if uploaded_file is not None and hasattr(st.session_state, 'last_file_name'):
        if uploaded_file.name != st.session_state.last_file_name:
            st.session_state.file_processed = False
            st.rerun()

    if st.session_state.file_processed:
        df = get_processed_dataframe(processor)

        if not df.empty:
            st.sidebar.header("Data Filters")
            available_protocols = ["All"] + \
                sorted(df['protocol'].unique().tolist())
            selected_protocol = st.sidebar.selectbox(
                "Filter by Protocol", available_protocols)
            available_sources = ["All"] + \
                sorted(df['source'].unique().tolist())
            selected_source = st.sidebar.selectbox(
                "Filter by Source IP", available_sources)
            available_destinations = ["All"] + \
                sorted(df['destination'].unique().tolist())
            selected_destination = st.sidebar.selectbox(
                "Filter by Destination IP", available_destinations)

            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                min_time = df['timestamp'].min().to_pydatetime()
                max_time = df['timestamp'].max().to_pydatetime()

                st.sidebar.header("Time Range")
                selected_time_range = st.sidebar.slider(
                    "Select Time Range",
                    min_value=min_time,
                    max_value=max_time,
                    value=(min_time, max_time)
                )

                filtered_df = df[(df['timestamp'] >= selected_time_range[0]) &
                                 (df['timestamp'] <= selected_time_range[1])]
            else:
                filtered_df = df.copy()

            if selected_protocol != "All":
                filtered_df = filtered_df[filtered_df['protocol']
                                          == selected_protocol]

            if selected_source != "All":
                filtered_df = filtered_df[filtered_df['source']
                                          == selected_source]

            if selected_destination != "All":
                filtered_df = filtered_df[filtered_df['destination']
                                          == selected_destination]

            st.sidebar.header("Filter Summary")
            st.sidebar.info(f"Showing {len(filtered_df)} of {len(df)} packets")

            if st.sidebar.button("Reset All Filters"):
                st.rerun()

            if st.sidebar.button("Clear Data and Upload New File"):
                st.session_state.file_processed = False
                st.rerun()

            st.sidebar.header("Navigation")
            page = st.sidebar.radio(
                "Select View",
                ["Overview", "Protocol Analysis", "Source/Destination Analysis",
                 "Timeline Analysis", "Raw Data"]
            )

            dashboard = Dashboard(filtered_df)

            if page == "Overview":
                st.header("Network Traffic Overview")
                st.markdown("Complete summary of processed network packets.")

                col1, col2 = st.columns(2)

                with col1:
                    st.metric("Total Packets", len(filtered_df))
                    if 'size' in filtered_df.columns:
                        avg_size = filtered_df['size'].mean()
                        st.metric("Average Packet Size",
                                  f"{avg_size:.2f} bytes")

                with col2:
                    protocol_count = len(filtered_df['protocol'].unique())
                    st.metric("Unique Protocols", protocol_count)
                    source_count = len(filtered_df['source'].unique())
                    st.metric("Unique Sources", source_count)

                dashboard.create_protocol_pie_chart()

                st.subheader("Top Traffic Sources and Destinations")
                col1, col2 = st.columns(2)
                with col1:
                    dashboard.create_source_ip_bar_chart()
                with col2:
                    dashboard.create_destination_ip_bar_chart()

            elif page == "Protocol Analysis":
                st.header("Protocol Analysis")
                st.markdown(
                    "Detailed analysis of network protocols in the capture file.")
                dashboard.create_protocol_pie_chart()

                protocols = filtered_df['protocol'].value_counts()
                st.subheader("Protocol Distribution")
                for protocol, count in protocols.items():
                    percentage = (count / len(filtered_df)) * 100
                    st.write(
                        f"**{protocol}**: {count} packets ({percentage:.2f}%)")

            elif page == "Source/Destination Analysis":
                st.header("Source/Destination Analysis")
                st.markdown(
                    "Analysis of traffic patterns between IP addresses.")

                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Top Source IP Addresses")
                    dashboard.create_source_ip_bar_chart()
                with col2:
                    st.subheader("Top Destination IP Addresses")
                    dashboard.create_destination_ip_bar_chart()

            elif page == "Timeline Analysis":
                st.header("Timeline Analysis")
                st.markdown("Temporal analysis of network traffic.")
                dashboard.create_datetime_line_chart()

            elif page == "Raw Data":
                st.header("Raw Packet Data")
                st.markdown("View the raw packet data in tabular format.")
                st.dataframe(filtered_df)

                csv = filtered_df.to_csv(index=False)
                st.download_button(
                    label="Download data as CSV",
                    data=csv,
                    file_name="packet_data.csv",
                    mime="text/csv",
                )
        else:
            st.warning("No IP packets found in the uploaded file.")
    elif uploaded_file is None:
        st.info("Please upload a PCAP file to visualize network data")

    st.markdown("---")
    st.markdown("Built with Streamlit, Plotly, and Scapy")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
