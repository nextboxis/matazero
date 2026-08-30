"""Renderer for dataset clustering reports."""

from __future__ import annotations
import json
from pathlib import Path

from rich.console import Console
from rich.tree import Tree
from rich.panel import Panel
from rich.text import Text

from imgint.core.cluster.engine import ClusterReport


class ClusterRenderer:
    """Renders ClusterReport as rich hierarchical terminal trees or JSON."""

    @classmethod
    def render_terminal(cls, report: ClusterReport, console: Console) -> None:
        panel_content = Text()
        panel_content.append(f"Total Clustered Evidence: ", style="dim")
        panel_content.append(f"{report.total_images} files\n", style="bold cyan")
        panel_content.append(f"Clustering Strategy:      ", style="dim")
        panel_content.append(f"{report.strategy.upper()}\n", style="yellow")
        panel_content.append(f"Identified Clusters:      ", style="dim")
        panel_content.append(f"{len(report.clusters)}\n", style="bold green")

        if report.outliers:
            panel_content.append(f"\n[!] Detected Anomalies / Outliers: {len(report.outliers)}\n", style="bold red")
            for o in report.outliers:
                panel_content.append(f" • {o.file_name}: {o.outlier_reason}\n", style="red")

        console.print(Panel(panel_content, title="[bold]matazero Evidence Dataset Clustering[/bold]", border_style="cyan"))

        root_tree = Tree(f"[bold]Evidence Fleet Hierarchy ({report.total_images} Assets)[/bold]")

        for c in report.clusters:
            c_node = root_tree.add(f"[bold green]{c.cluster_label}[/bold green] [dim]({c.item_count} items)[/dim]")
            for it in c.items:
                status_color = "red" if it.is_outlier or it.risk_level == "HIGH" else "yellow" if it.risk_level == "MEDIUM" else "cyan"
                extra_parts = []
                if it.camera_model:
                    extra_parts.append(it.camera_model)
                if it.dqt_hash and it.dqt_hash != "no_dqt":
                    extra_parts.append(f"DQT:{it.dqt_hash}")
                if it.gps_coordinates:
                    extra_parts.append(f"GPS:{it.gps_coordinates[0]:.2f},{it.gps_coordinates[1]:.2f}")
                extra_str = f" [dim]({', '.join(extra_parts)})[/dim]" if extra_parts else ""
                
                outlier_badge = " [bold red][OUTLIER][/bold red]" if it.is_outlier else ""
                c_node.add(f"[{status_color}]{it.file_name}[/{status_color}]{outlier_badge}{extra_str}")

        console.print(root_tree)

    @classmethod
    def render_json(cls, report: ClusterReport) -> str:
        return json.dumps(report.to_dict(), indent=2)
