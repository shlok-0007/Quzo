#!/usr/bin/env python3
"""
Utility script to manage API keys
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from api_utils import APIKeyManager

def reactivate_all_keys():
    """Reactivate all API keys (useful when quotas reset)"""
    manager = APIKeyManager()
    manager.reactivate_all_keys()
    print("✅ All API keys have been reactivated!")

def show_key_status():
    """Show current status of all API keys"""
    manager = APIKeyManager()
    print("API Key Status:")
    print("=" * 50)
    
    keys = manager.data.get('keys', [])
    key_status = manager.data.get('key_status', {})
    
    for i, key in enumerate(keys, 1):
        status = key_status.get(key, {})
        active = status.get('is_active', True)
        usage = status.get('usage_count', 0)
        last_used = status.get('last_used', 'Never')
        
        status_icon = "✅" if active else "❌"
        print(f"{status_icon} Key {i}: {key[:15]}... (Usage: {usage}, Last: {last_used})")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Manage API keys')
    parser.add_argument('--reactivate', action='store_true', help='Reactivate all API keys')
    parser.add_argument('--status', action='store_true', help='Show key status')
    
    args = parser.parse_args()
    
    if args.reactivate:
        reactivate_all_keys()
    elif args.status:
        show_key_status()
    else:
        print("Usage: python manage_keys.py --status | --reactivate")
        show_key_status()
