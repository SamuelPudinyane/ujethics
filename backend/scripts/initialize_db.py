from models import Base, engine

def create_tables():
    """Create all tables defined in models.py."""
    print("Creating tables...")
    Base.metadata.create_all(engine)
    print("Tables created successfully!")

if __name__ == "__main__":
    create_tables()