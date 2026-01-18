import click
from rich.console import Console
from rich.table import Table
from .database.db_manager import DBManager
from .core.enumerator import ServiceEnumerator
from .database.models import Service

console = Console()

@click.group()
def cli():
    """MachSpec - XPC Fuzzer & Capability Mapper"""
    pass

@cli.command()
def version():
    """Show version info"""
    console.print("[bold green]MachSpec v0.1.0[/bold green]")

@cli.command()
@click.option('--db-path', default="machspec.db", help="Path to SQLite database")
def enumerate(db_path):
    """Enumerate system XPC services and populate database."""
    console.print(f"[bold blue]Starting MachSpec Service Enumeration...[/bold blue]")
    
    db_manager = DBManager(db_path)
    db_manager.init_db()
    session = db_manager.get_session()
    
    enumerator = ServiceEnumerator(session)
    enumerator.scan_system()
    
    # Show summary
    count = session.query(Service).count()
    console.print(f"[bold green]Enumeration Complete. Found {count} services.[/bold green]")
    session.close()

@cli.command()
@click.option('--db-path', default="machspec.db", help="Path to SQLite database")
def list_services(db_path):
    """List discovered services from the database."""
    db_manager = DBManager(db_path)
    session = db_manager.get_session()
    
    services = session.query(Service).all()
    
    table = Table(title="Discovered XPC Services")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Binary", style="green")
    table.add_column("Root?", style="red")
    
    for svc in services:
        table.add_row(str(svc.id), svc.name, svc.binary_path or "N/A", "Yes" if svc.is_root else "No")
        
    console.print(table)
    session.close()

@cli.command()
@click.argument('target')
@click.option('--spawn/--attach', default=True, help="Spawn new process or attach to existing")
def profile(target, spawn):
    """Profile a target binary or service name dynamically."""
    from .core.dynamic_profiler import DynamicProfiler
    
    profiler = DynamicProfiler(target, is_spawn=spawn)
    profiler.start()

@cli.command()
@click.argument('service_name')
@click.option('--iterations', default=100, help="Number of iterations")
@click.option('--binary', default=None, help="Path to XPCClient binary")
def fuzz(service_name, iterations, binary):
    """Fuzz an XPC service with random messages."""
    from .fuzzer.engine import FuzzEngine
    
    console.print(f"[bold red]Starting Fuzzer for {service_name} ({iterations} iters)...[/bold red]")
    engine = FuzzEngine(service_name, binary_path=binary)
    engine.fuzz(iterations=iterations)

@cli.command()
@click.argument('service_name')
@click.option('--binary', default=None, help="Path to XPCClient binary")
def auth_test(service_name, binary):
    """Test authentication and entitlement checks."""
    from .auth.tester import AuthTester
    
    tester = AuthTester(service_name, binary_path=binary)
    result = tester.test_connection_validity()
    
    console.print(f"[bold]Auth Test Result for {service_name}:[/bold]")
    console.print(result)

@cli.command()
@click.option('--db-path', default="machspec.db", help="Path to SQLite database")
@click.option('--format', type=click.Choice(['json', 'txt'], case_sensitive=False), default='json')
def export_report(db_path, format):
    """Export service capability map and findings."""
    import json
    db_manager = DBManager(db_path)
    session = db_manager.get_session()
    
    services = session.query(Service).all()
    results = []
    for svc in services:
        results.append({
            "name": svc.name,
            "binary": svc.binary_path,
            "is_root": svc.is_root,
            "entitlements": svc.entitlements,
            "codesign": svc.codesign_requirements,
            "source": svc.discovery_source
        })
    
    if format == 'json':
        console.print(json.dumps(results, indent=2))
    else:
        for r in results:
            console.print(f"Service: {r['name']}")
            console.print(f"  Binary: {r['binary']}")
            console.print(f"  Root: {r['is_root']}")
            console.print("-" * 20)
            
    session.close()

if __name__ == "__main__":
    cli()
