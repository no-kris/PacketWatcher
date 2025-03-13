import asyncio
import logging
import os
import tempfile
import streamlit as st

from dashboard import Dashboard
from process_packet import PacketProcessor


async def test():
    processor = PacketProcessor()

    pcap_file = "set3.pcap"
    count = await processor.process_packets(pcap_file)

    print(f"Processed {count} packets from {pcap_file}")

    analysis = await processor.packet_stats()
    print("Analysis results:")
    for key, value in analysis.items():
        print(f"{key}: {value}")

    df = processor.get_dataframe()
    if not df.empty:
        print("\nSample of processed data:")
        print(df.head())


async def main():
    # await test()

    st.set_page_config(
        page_title="Packet Watcher",
        page_icon="🔍",
        layout="wide"
    )

    st.title("Packet Watcher - Packet Analysis Dashboard")
    st.subheader("Packet Watcher is a web based data analysis program that allows you to view packet information"
                 "in a nice user interface manner.")
    st.markdown(
        "Upload a PCAP file to analyze network traffic patterns and statistics.")

    uploaded_file = st.file_uploader(
        "Choose a PCAP file", type=['pcap', 'pcapng'])

    if 'processor' not in st.session_state:
        st.session_state.processor = PacketProcessor()

    if uploaded_file is not None:
        with st.spinner("Processing packet data... feel free to leave and come back when finished."):
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                temp_path = tmp_file.name

            try:
                processor = st.session_state.processor
                count = await processor.process_packets(temp_path)
                df = processor.get_dataframe()

                if not df.empty:
                    st.success(f"Successfully processed {count} packets")
                    dashboard = Dashboard(df)
                    dashboard.create_visualiztions()
                else:
                    st.warning("No IP packets found in the uploaded file.")

            except Exception as e:
                st.error(f"Error processing file: {str(e)}")

            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
    else:
        st.info("Please upload a PCAP file to visualize network data")

    # Add sidebar for filtering (optional enhancement)
    if 'processor' in st.session_state and not st.session_state.processor.get_dataframe().empty:
        df = st.session_state.processor.get_dataframe()
        st.sidebar.header("Analysis Controls")

        # Add filters here if desired

    st.markdown("---")
    st.markdown("Built with Streamlit, Plotly, and Scapy")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
