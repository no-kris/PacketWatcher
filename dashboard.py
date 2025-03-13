import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go


class Dashboard(object):
    """Dashboard class for creating visualizations for packet data."""

    def __init__(self, df: pd.DataFrame):
        self.__data_frame = df

    def create_protocol_pie_chart(self):
        """Create a pie chart showing the distribution of protocols in packet file."""
        protocol_counts = self.__data_frame['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution"
        )
        st.plotly_chart(fig_protocol, use_container_width=True)

    def create_datetime_line_chart(self):
        """Create a timeline showing packets processed per second."""
        df = self.__data_frame
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor(
            's')).size().reset_index(name='count')
        fig_timeline = px.line(
            x=df_grouped['timestamp'],
            y=df_grouped['count'],
            title="Packets per second"
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

    def create_source_ip_bar_chart(self):
        """Create a bar chart showing top IP source addresses."""
        df = self.__data_frame
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top IP Source Addresses"
        )
        st.plotly_chart(fig_sources, use_container_width=True)

    def create_destination_ip_bar_chart(self):
        """Create a bar chart showing top IP destinations addresses."""
        df = self.__data_frame
        top_destinations = df['destination'].value_counts().head(10)
        fig_destinations = px.bar(
            x=top_destinations.index,
            y=top_destinations.values,
            title="Top IP destinations Addresses"
        )
        st.plotly_chart(fig_destinations, use_container_width=True)

    def create_statistics_table(self):
        fig = go.Figure(data=[go.Table(
            header=dict(
                values=list(self.__data_frame.columns),
                fill_color='royalblue',
                align='left',
                font=dict(color='white', size=12)
            ),
            cells=dict(
                values=[self.__data_frame[col]
                        for col in self.__data_frame.columns],
                fill_color='lavender',
                align='left',
                height=30
            )
        )])

        fig.update_layout(
            title="Packet Analysis Summary",
            height=400,
            margin=dict(l=20, r=20, t=60, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)

    def create_visualiztions(self):
        if len(self.__data_frame) > 0:
            self.create_statistics_table()
            self.create_protocol_pie_chart()
            self.create_source_ip_bar_chart()
            self.create_destination_ip_bar_chart()
            self.create_datetime_line_chart()
