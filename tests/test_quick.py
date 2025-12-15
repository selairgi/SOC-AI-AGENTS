"""Quick test to verify the system works"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

print("Testing imports...")

try:
    from shared.agent_memory import AgentMemory
    print("✓ AgentMemory imported")
    
    from core.soc_builder import SOCBuilder
    print("✓ SOCBuilder imported")
    
    from core.soc_analyst import SOCAnalyst
    print("✓ SOCAnalyst imported")
    
    from core.remediator import Remediator
    print("✓ Remediator imported")
    
    # Test memory
    memory = AgentMemory(db_path=":memory:")
    stats = memory.get_statistics()
    print(f"✓ Memory initialized: {stats}")
    
    # Test builder
    from shared.message_bus import MessageBus
    bus = MessageBus()
    builder = SOCBuilder(bus, memory=memory)
    print(f"✓ Builder initialized: {builder.stats['patterns_loaded']} patterns loaded")
    
    print("\n✅ All tests passed! The system is ready to use.")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

