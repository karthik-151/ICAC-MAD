"""
Setup script to initialize the Cloud Security System.
"""
import os
from pathlib import Path

def create_directories():
    """Create necessary directories."""
    dirs = [
        'data/raw',
        'data/processed',
        'models',
        'static',
        'templates',
        'modules'
    ]
    
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {dir_path}")


def create_env_file():
    """Create .env file if it doesn't exist."""
    if not os.path.exists('.env'):
        with open('.env.example', 'r') as src:
            with open('.env', 'w') as dst:
                dst.write(src.read())
        print("✓ Created .env file from template")
        print("  ⚠ Please edit .env with your AWS credentials")
    else:
        print("✓ .env file already exists")


def main():
    """Run setup."""
    print("="*60)
    print("CLOUD SECURITY SYSTEM - SETUP")
    print("="*60)
    
    print("\n1. Creating directories...")
    create_directories()
    
    print("\n2. Setting up environment file...")
    create_env_file()
    
    print("\n" + "="*60)
    print("SETUP COMPLETE!")
    print("="*60)
    print("\nNext steps:")
    print("  1. Edit .env with your AWS credentials")
    print("  2. Install dependencies: pip install -r requirements.txt")
    print("  3. Run tests: python test_system.py")
    print("  4. Generate sample data: python generate_sample_data.py")
    print("  5. Train model: python train.py")
    print("  6. Start dashboard: flask run --host=0.0.0.0 --port=5000")
    print("="*60)


if __name__ == '__main__':
    main()
