import asyncio
import logging
import os
import tempfile
import streamlit as st

from dashboard import Dashboard
from process_packet import PacketProcessor

st.set_page_config(page_title="Packet Watcher",
                   page_icon="🔍", layout="wide")


class PacketWatcherApp:
    """Class implementation of the Packet Watcher App"""

    def __init__(self):
        self.processor = self.get_processor()
        self.uploaded_file = None
        self.filtered_df = None

    @st.cache_resource
    def get_processor(_dummy=None):
        """Create and cache a processor instance"""
        return PacketProcessor()

    @st.cache_data
    def get_processed_dataframe(_self):
        """Return cached dataframe to avoid reprocessing"""
        return _self.processor.get_dataframe()

    async def process_file(self, file_path):
        """Process the file and return packet count"""
        return await self.processor.process_packets(file_path)

    def setup_sidebar(self):
        """Set up sidebar elements"""
        st.sidebar.title("Network Analysis Dashboard")

        with st.sidebar.expander("About", expanded=False):
            st.write("""
            This dashboard analyzes PCAP files to provide insights into network traffic patterns,
            protocol distributions, and potential threats.
            """)

        self.uploaded_file = st.sidebar.file_uploader(
            "Choose a PCAP file", type=['pcap', 'pcapng'])

        if st.sidebar.button("Clear Data and Upload New File"):
            st.session_state.file_processed = False
            self.uploaded_file = None
            st.cache_data.clear()
            st.cache_resource.clear()

    async def handle_file_upload(self):
        """Handle file upload and processing"""
        if self.uploaded_file and not st.session_state.get("file_processed", False):
            with st.spinner("Processing packet data... Please wait."):
                with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
                    tmp_file.write(self.uploaded_file.getvalue())
                    temp_path = tmp_file.name

                try:
                    count = await self.process_file(temp_path)
                    st.session_state.file_processed = True
                    st.session_state.last_file_name = self.uploaded_file.name
                    st.success(f"Successfully processed {count} packets")

                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")

                finally:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)

    def filter_dataframe(self):
        """Apply user-selected filters to the dataframe"""
        df = self.get_processed_dataframe()

        if df.empty:
            st.warning("No IP packets found in the uploaded file.")
            return None

        st.sidebar.header("Data Filters")

        available_protocols = ["All"] + \
            sorted(df['protocol'].unique().tolist())
        selected_protocol = st.sidebar.selectbox(
            "Filter by Protocol", available_protocols)

        available_sources = ["All"] + sorted(df['source'].unique().tolist())
        selected_source = st.sidebar.selectbox(
            "Filter by Source IP", available_sources)

        available_destinations = ["All"] + \
            sorted(df['destination'].unique().tolist())
        selected_destination = st.sidebar.selectbox(
            "Filter by Destination IP", available_destinations)

        if selected_protocol != "All":
            df = df[df['protocol'] == selected_protocol]

        if selected_source != "All":
            df = df[df['source'] == selected_source]

        if selected_destination != "All":
            df = df[df['destination'] == selected_destination]

        st.sidebar.header("Filter Summary")
        st.sidebar.info(
            f"Showing {len(df)} of {len(self.get_processed_dataframe())} packets")

        return df

    def show_overview(self, dashboard):
        """Display overview of data."""
        st.header("Network Traffic Overview")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Packets", len(self.filtered_df))
            if 'size' in self.filtered_df.columns:
                avg_size = self.filtered_df['size'].mean()
                st.metric("Average Packet Size",
                          f"{avg_size:.2f} bytes")

        with col2:
            protocol_count = len(self.filtered_df['protocol'].unique())
            st.metric("Unique Protocols", protocol_count)
            source_count = len(self.filtered_df['source'].unique())
            st.metric("Unique Sources", source_count)

        dashboard.create_protocol_pie_chart()

        st.subheader("Top Traffic Sources and Destinations")
        col1, col2 = st.columns(2)
        with col1:
            dashboard.create_source_ip_bar_chart()
        with col2:
            dashboard.create_destination_ip_bar_chart()

    def show_protocol_analysis(self, dashboard):
        """Display protocol distribution pi chart and protocol distribution breakdown."""
        st.header("Protocol Analysis")
        st.markdown(
            "Detailed analysis of network protocols in the capture file.")
        dashboard.create_protocol_pie_chart()
        protocols = self.filtered_df['protocol'].value_counts()
        st.subheader("Protocol Distribution Breakdown")
        for protocol, count in protocols.items():
            percentage = (count / len(self.filtered_df)) * 100
            st.write(
                f"**{protocol}**: {count} packets ({percentage:.2f}%)")

    def show_src_dst_analysis(self, dashboard):
        st.header("Source/Destination Analysis")
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Top Source IP Addresses")
            dashboard.create_source_ip_bar_chart()
        with col2:
            st.subheader("Top Destination IP Addresses")
            dashboard.create_destination_ip_bar_chart()

    def show_raw_data(self):
        """Show tabular network data and provide option to download as csv file."""
        st.header("Raw Packet Data")
        st.dataframe(self.filtered_df)

        csv = self.filtered_df.to_csv(index=False)
        st.download_button(
            label="Download data as CSV",
            data=csv,
            file_name="packet_data.csv",
            mime="text/csv",
        )

    def display_dashboard(self):
        """Display the selected dashboard page"""
        if not self.filtered_df.empty:
            st.sidebar.header("Navigation")
            page = st.sidebar.radio(
                "Select View",
                ["Overview", "Protocol Analysis", "Source/Destination Analysis",
                 "Timeline Analysis", "Raw Data"]
            )

            dashboard = Dashboard(self.filtered_df)

            if page == "Overview":
                self.show_overview(dashboard)

            elif page == "Protocol Analysis":
                self.show_protocol_analysis(dashboard)

            elif page == "Source/Destination Analysis":
                self.show_src_dst_analysis(dashboard)

            elif page == "Timeline Analysis":
                st.header("Timeline Analysis")
                dashboard.create_datetime_line_chart()

            elif page == "Raw Data":
                self.show_raw_data()

    async def run(self):
        """Run the Streamlit application"""

        st.title("Packet Watcher - Network Analysis")
        st.markdown(
            "Upload a PCAP file to analyze network traffic patterns and statistics.")

        self.setup_sidebar()

        if self.uploaded_file:
            await self.handle_file_upload()

        if st.session_state.get("file_processed", False):
            self.filtered_df = self.filter_dataframe()
            if self.filtered_df is not None:
                self.display_dashboard()

        st.markdown("---")
        st.markdown("Built with Streamlit, Plotly, and Scapy")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app = PacketWatcherApp()
    asyncio.run(app.run())
