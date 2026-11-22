import os
from app.rag.loader import load_cti_csv

def test():
    # Path to the sample CSV
    csv_path = os.path.join("data", "raw", "csv", "1_otx_threat_intel.csv")
    
    print(f"Testing loader with file: {csv_path}")
    
    try:
        documents = load_cti_csv(csv_path)
        print(f"Successfully loaded {len(documents)} documents!")
        
        if documents:
            print("\n--- First Document Sample ---")
            print("Content:\n")
            print(documents[0].page_content)
            print("\n--- Metadata ---")
            for key, value in documents[0].metadata.items():
                print(f"{key}: {value}")
            print("-----------------------------")
            
    except Exception as e:
        print(f"Error loading CSV: {e}")

if __name__ == "__main__":
    test()
