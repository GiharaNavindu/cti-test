"""
STIX Data Visualization Module
Provides interactive and static visualizations for STIX threat data
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Tuple
import networkx as nx
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from stix2 import parse


class STIXVisualizer:
    """Handles visualization of STIX bundles and threat data"""
    
    def __init__(self, output_dir: str = "processed_data/visualizations"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.graph = nx.DiGraph()
        self.objects_data = []
        
    def load_bundle(self, bundle_path: str) -> Dict:
        """Load STIX bundle from JSON file"""
        try:
            with open(bundle_path, 'r') as f:
                if bundle_path.endswith('.gz'):
                    import gzip
                    with gzip.open(bundle_path, 'rt') as gz:
                        data = json.load(gz)
                else:
                    data = json.load(f)
            return data
        except Exception as e:
            print(f"Error loading bundle {bundle_path}: {e}")
            return {}
    
    def extract_graph_data(self, bundle_data: Dict) -> Tuple[nx.DiGraph, List[Dict]]:
        """Extract relationships and objects from STIX bundle"""
        graph = nx.DiGraph()
        objects = []
        
        # Handle both direct object list and bundle structure
        bundle_objects = bundle_data.get('objects', []) if isinstance(bundle_data, dict) else bundle_data
        
        for obj in bundle_objects:
            if not isinstance(obj, dict):
                continue
                
            obj_type = obj.get('type', 'unknown')
            obj_id = obj.get('id', 'unknown')
            name = obj.get('name', obj_id.split('--')[-1])
            description = obj.get('description', '')[:100]  # Truncate for readability
            
            # Add node to graph
            graph.add_node(obj_id, 
                          name=name,
                          type=obj_type,
                          description=description)
            
            # Store object data
            objects.append({
                'id': obj_id,
                'type': obj_type,
                'name': name,
                'full_description': obj.get('description', ''),
                'created': obj.get('created', ''),
                'modified': obj.get('modified', '')
            })
        
        # Extract relationships
        for obj in bundle_objects:
            if isinstance(obj, dict) and obj.get('type') == 'relationship':
                source = obj.get('source_ref')
                target = obj.get('target_ref')
                rel_type = obj.get('relationship_type', 'unknown')
                
                if source and target:
                    graph.add_edge(source, target, relationship=rel_type)
        
        return graph, objects
    
    def create_interactive_graph(self, graph: nx.DiGraph, title: str, output_file: str):
        """Create interactive Plotly network graph"""
        if len(graph.nodes()) == 0:
            print(f"No data to visualize for {title}")
            return
        
        # Use spring layout for better visualization
        pos = nx.spring_layout(graph, k=2, iterations=50, seed=42)
        
        # Prepare edge traces
        edge_x = []
        edge_y = []
        
        for edge in graph.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            mode='lines',
            line=dict(width=0.5, color='#888'),
            hoverinfo='none',
            showlegend=False
        )
        
        # Prepare node traces with color coding by type
        node_x = []
        node_y = []
        node_color = []
        node_text = []
        node_size = []
        
        # Color mapping for different STIX types
        color_map = {
            'attack-pattern': '#FF6B6B',
            'malware': '#FF8C42',
            'tool': '#4ECDC4',
            'campaign': '#45B7D1',
            'identity': '#96CEB4',
            'relationship': '#FFEAA7',
            'extension-definition': '#DDA15E'
        }
        
        for node in graph.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            node_attrs = graph.nodes[node]
            node_type = node_attrs.get('type', 'unknown')
            node_color.append(color_map.get(node_type, '#CCCCCC'))
            node_text.append(f"{node_attrs.get('name', node)}<br>Type: {node_type}<br>{node_attrs.get('description', '')}")
            
            # Size based on node degree
            node_size.append(15 + graph.degree(node) * 2)
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            marker=dict(
                color=node_color,
                size=node_size,
                line=dict(color='white', width=2)
            ),
            text=node_text,
            hoverinfo='text',
            showlegend=False
        )
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace])
        
        fig.update_layout(
            title=title,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=0, l=0, r=0, t=40),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            plot_bgcolor='#f8f9fa',
            height=700,
            width=1200
        )
        
        fig.write_html(output_file)
        print(f"✓ Interactive graph saved: {output_file}")
    
    def create_statistics_dashboard(self, attack_objects: List[Dict], fight_objects: List[Dict], output_file: str):
        """Create statistics dashboard comparing ATT&CK and FiGHT data"""
        
        # Count by type
        attack_types = {}
        fight_types = {}
        
        for obj in attack_objects:
            obj_type = obj['type']
            attack_types[obj_type] = attack_types.get(obj_type, 0) + 1
        
        for obj in fight_objects:
            obj_type = obj['type']
            fight_types[obj_type] = fight_types.get(obj_type, 0) + 1
        
        # Combine all types
        all_types = sorted(set(attack_types.keys()) | set(fight_types.keys()))
        attack_counts = [attack_types.get(t, 0) for t in all_types]
        fight_counts = [fight_types.get(t, 0) for t in all_types]
        
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Objects by Type (ATT&CK)", "Objects by Type (FiGHT)",
                          "Total Objects Comparison", "Data Overlap Analysis"),
            specs=[[{"type": "bar"}, {"type": "bar"}],
                   [{"type": "Bar"}, {"type": "pie"}]]
        )
        
        # ATT&CK bar chart
        fig.add_trace(
            go.Bar(x=all_types, y=attack_counts, name='ATT&CK', marker_color='#FF6B6B'),
            row=1, col=1
        )
        
        # FiGHT bar chart
        fig.add_trace(
            go.Bar(x=all_types, y=fight_counts, name='FiGHT', marker_color='#4ECDC4'),
            row=1, col=2
        )
        
        # Comparison bar
        fig.add_trace(
            go.Bar(name='ATT&CK', x=['Total Objects'], y=[len(attack_objects)], marker_color='#FF6B6B'),
            row=2, col=1
        )
        fig.add_trace(
            go.Bar(name='FiGHT', x=['Total Objects'], y=[len(fight_objects)], marker_color='#4ECDC4'),
            row=2, col=1
        )
        
        # Pie chart for overlap
        overlap_labels = ['ATT&CK Only', 'FiGHT Only', 'Both']
        overlap_values = [len(attack_objects) - len(fight_objects), len(fight_objects), min(len(attack_objects), len(fight_objects))]
        
        fig.add_trace(
            go.Pie(labels=overlap_labels, values=overlap_values, marker_colors=['#FF6B6B', '#4ECDC4', '#96CEB4']),
            row=2, col=2
        )
        
        fig.update_xaxes(title_text="STIX Type", row=1, col=1)
        fig.update_yaxes(title_text="Count", row=1, col=1)
        fig.update_xaxes(title_text="STIX Type", row=1, col=2)
        fig.update_yaxes(title_text="Count", row=1, col=2)
        
        fig.update_layout(height=900, title_text="Threat Data Statistics Dashboard", showlegend=True)
        fig.write_html(output_file)
        print(f"✓ Statistics dashboard saved: {output_file}")
    
    def create_heatmap(self, graph: nx.DiGraph, title: str, output_file: str):
        """Create adjacency heatmap for network analysis"""
        if len(graph.nodes()) == 0:
            return
        
        # Limit nodes for readability
        nodes = list(graph.nodes())[:30]  # Top 30 nodes
        
        # Create adjacency matrix
        adj_matrix = nx.to_numpy_array(graph.subgraph(nodes), nodelist=nodes)
        node_names = [graph.nodes[node].get('name', node)[:20] for node in nodes]
        
        fig = go.Figure(data=go.Heatmap(
            z=adj_matrix,
            x=node_names,
            y=node_names,
            colorscale='RdBu'
        ))
        
        fig.update_layout(
            title=title,
            xaxis_title="Target",
            yaxis_title="Source",
            height=600,
            width=700
        )
        
        fig.write_html(output_file)
        print(f"✓ Heatmap saved: {output_file}")
    
    def visualize_threat_data(self, attack_bundle_path: str, fight_bundle_path: str):
        """Main method to visualize both threat datasets"""
        print("\n" + "="*60)
        print("STIX Data Visualization")
        print("="*60)
        
        # Load bundles
        print("\nLoading threat data...")
        attack_data = self.load_bundle(attack_bundle_path)
        fight_data = self.load_bundle(fight_bundle_path)
        
        # Extract graphs and objects
        print("Extracting graph structures...")
        attack_graph, attack_objects = self.extract_graph_data(attack_data)
        fight_graph, fight_objects = self.extract_graph_data(fight_data)
        
        print(f"  ATT&CK: {len(attack_objects)} objects, {len(attack_graph.edges())} relationships")
        print(f"  FiGHT: {len(fight_objects)} objects, {len(fight_graph.edges())} relationships")
        
        # Create visualizations
        print("\nGenerating visualizations...")
        
        # Interactive graphs
        self.create_interactive_graph(
            attack_graph,
            "ATT&CK Threat Framework - Interactive Network",
            f"{self.output_dir}/attack_threat_network.html"
        )
        
        self.create_interactive_graph(
            fight_graph,
            "FiGHT Framework - Interactive Network",
            f"{self.output_dir}/fight_threat_network.html"
        )
        
        # Statistics dashboard
        self.create_statistics_dashboard(
            attack_objects,
            fight_objects,
            f"{self.output_dir}/statistics_dashboard.html"
        )
        
        # Heatmaps (if graphs have connections)
        if len(attack_graph.edges()) > 0:
            self.create_heatmap(
                attack_graph,
                "ATT&CK Threat Relationships - Heatmap",
                f"{self.output_dir}/attack_heatmap.html"
            )
        
        if len(fight_graph.edges()) > 0:
            self.create_heatmap(
                fight_graph,
                "FiGHT Threat Relationships - Heatmap",
                f"{self.output_dir}/fight_heatmap.html"
            )
        
        print(f"\n✓ All visualizations generated in: {self.output_dir}")
        return {
            'attack_objects': attack_objects,
            'fight_objects': fight_objects,
            'attack_graph': attack_graph,
            'fight_graph': fight_graph
        }


def visualize_and_print_summary(attack_bundle_path: str, fight_bundle_path: str):
    """Main entry point for visualization"""
    visualizer = STIXVisualizer()
    results = visualizer.visualize_threat_data(attack_bundle_path, fight_bundle_path)
    
    # Print summary
    print("\n" + "="*60)
    print("VISUALIZATION SUMMARY")
    print("="*60)
    print(f"Total ATT&CK Objects: {len(results['attack_objects'])}")
    print(f"Total FiGHT Objects: {len(results['fight_objects'])}")
    print(f"Total Threat Relationships: {len(results['attack_graph'].edges()) + len(results['fight_graph'].edges())}")
    print("="*60)
    
    return results
