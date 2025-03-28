import pandas as pd
import streamlit as st
import plotly.express as px
from threat_analyzer import ThreatAnalyzer


class ThreatAnalysisDashboard(object):
    """Class to display threat analysis dashboard"""

    def __init__(self, filtered_df: pd.DataFrame):
        """Initialize the threat analysis dashboard with the filtered pandas dataframe."""
        self.__filtered_df: pd.DataFrame = filtered_df
        self.__threat_analyzer = ThreatAnalyzer(filtered_df)
        self.__threat_analyzer.build_network_graph()

    def run(self):
        """Main method for running dashboard.
           Initialized the different tabs."""
        st.header("Threat Analysis Dashboard")

        tab1, tab2, tab3, tab4 = st.tabs([
            "Network traffic overview",
            "Traffic Analysis",
            "Exchange Ratios",
            "Network Graph"
        ])

        with tab1:
            self.show_network_traffic_overview()
            self.show_ports_analysis()

        with tab2:
            self.show_traffic_analysis()

        with tab3:
            self.show_exchange_ratios()

        with tab4:
            self.show_network_graph()

    def show_network_traffic_overview(self):
        """Display an overview for the network traffic."""
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Total Network Devices",
                      self.__threat_analyzer.get_network_graph_len())

        with col2:
            solicitor_node = self.__threat_analyzer.find_solicitor_node()
            st.metric("Most Connected Node",
                      solicitor_node[0] if solicitor_node else "N/A",
                      solicitor_node[1] if solicitor_node else "0")

    def show_ports_analysis(self):
        """Visualize the top active ports and the nodes on those ports."""
        st.subheader("Top Active Ports")
        port_out_degrees = self.__threat_analyzer.get_highest_weighted_out_degree_for_ports()
        if port_out_degrees:
            port_df = pd.DataFrame.from_dict(
                port_out_degrees,
                orient='index',
                columns=['Most Active Node', 'Traffic Weight']
            ).reset_index().rename(columns={'index': 'Port'})
            fig = px.scatter(
                port_df,
                x="Port",
                y="Traffic Weight",
                size="Traffic Weight",
                color="Traffic Weight",
                hover_data=['Most Active Node', 'Port'],
                title="Traffic Weight by Port",
                log_x=True
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No port traffic data available.")

    def show_traffic_analysis(self):
        pass

    def _get_user_defined_z_score(self):
        """Helper method for getting a user defined z score."""
        z_score = st.number_input(
            "Z-score to use... (between 0.90 and 0.99)", min_value=0.90, max_value=0.99)
        return float(z_score)

    def show_exchange_ratios(self):
        """Display a scatter plot showing nodes and their information exchange ratio."""
        st.subheader("Information Exchange Ratio Analysis")
        z_score = self._get_user_defined_z_score()
        exchange_outliers = self.__threat_analyzer.get_exchange_ratio_outliers(
            z_score=z_score)

        if exchange_outliers:
            exchange_df = pd.DataFrame(
                exchange_outliers,
                columns=['Node', 'Exchange Ratio']
            )
            fig = px.scatter(
                exchange_df,
                x='Node',
                y='Exchange Ratio',
                color='Exchange Ratio',
                title='Node Information Exchange Ratios',
                labels={'Exchange Ratio': 'Ratio of In/Out Traffic',
                        'Node Address': 'Node'}
            )
            st.plotly_chart(fig, use_container_width=True)
            st.subheader("Exchange Ratio Outliers")
            st.dataframe(exchange_df)
        else:
            st.info("No unusual information exchange patterns detected.")

    def show_network_graph(self):
        pass
