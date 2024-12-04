# **STIX Converter Documentation**

## **Overview**

The STIX Converter script processes security data sources (e.g., Mandiant, Recorded Future) into the STIX 2.0 format. It transforms the input JSON files into STIX bundles, which are saved in JSON format.

## **Prerequisites**

Before running the script, ensure you have the required Python environment and dependencies installed.

---

## **Setting Up the Environment**

### **1\. Install Python**

Ensure Python 3.6 or higher is installed. Check your Python version:

`python3 --version`

### **2\. Set Up a Virtual Environment**

Navigate to the project directory:

`cd /path/to/project`


Create a virtual environment:

`python3 -m venv venv`

Activate the virtual environment:

**macOS/Linux**:

`source venv/bin/activate`



**Windows (Command Prompt)**:

`venv\Scripts\activate`



**Windows (PowerShell)**:

`.\venv\Scripts\Activate.ps1`



Install required dependencies:

`pip install -r requirements.txt`



---

## **Running the Script**

### **1\. Directory Setup**

Ensure your directory is structured as follows:

`stix_converter.py          # Main script`  
`responses/                 # Directory for input JSON files`  
    `mandiantMalware.json`  
    `recordedFuture.json`  
`stix_outputs/              # Directory where output STIX files will be saved`  
`requirements.txt           # Python package dependencies`

* **Input Files**: Place all JSON files to be processed in the `responses/` directory.  
* **Output Files**: Processed STIX bundles will be saved in the `stix_outputs/` directory.

### **2\. Run the Script**

Run the script from the project root directory:

`python stix_converter.py`

### **3\. Output**

For each input JSON file in the `responses/` directory:

* A corresponding STIX file is created in the `stix_outputs/` directory.  
* The output file will have the same name as the input file, with `.stix.json` appended.

Example:

`responses/mandiantMalware.json → stix_outputs/mandiantMalware.json.stix.json`

---

## **How It Works**

1. **Input Parsing**:  
   * The script reads `.json` files from the `responses/` directory.  
   * Each file is identified based on its type (e.g., Mandiant MD5, Recorded Future).  
2. **STIX Object Creation**:  
   * The script processes the data and converts it into relevant STIX objects (e.g., `Indicator`, `Campaign`, `ThreatActor`, `Malware`).  
   * These objects are bundled into a STIX `Bundle`.  
3. **Output**:  
   * The STIX bundle is saved in the `stix_outputs/` directory.

---

## **Error Handling**

* **Unsupported File Types**: If a file does not match any supported types, it will be skipped with a warning logged.  
* **Missing Required Fields**: If required fields are missing from the input JSON, an error will be logged, and the file will be skipped.  
* **General Errors**: Any unexpected errors will be logged, and the script will proceed with the next file.

---

## **Example**

### **Input File: `responses/mandiantMalware.json`**

json

`{`  
    `"id": "md5--5e295555-1eb1-56da-a781-bace7d15afc9",`  
    `"mscore": 100,`  
    `"value": "2da4f427f42dd7798d262b58a4d629d0",`  
    `"first_seen": "2023-05-03T04:19:10.000Z",`  
    `"last_seen": "2023-08-09T13:23:50.000Z"`  
`}`

### **Output File: `stix_outputs/mandiantMalware.json.stix.json`**

json

`{`  
    `"type": "bundle",`  
    `"id": "bundle--855ebea1-11c4-46cb-8f47-3c9d4b3ea91d",`  
    `"objects": [`  
        `{`  
            `"type": "indicator",`  
            `"spec_version": "2.1",`  
            `"id": "indicator--5e295555-1eb1-56da-a781-bace7d15afc9",`  
            `"created": "2023-05-03T04:19:10.000Z",`  
            `"modified": "2023-08-09T13:23:50.000Z",`  
            `"name": "Mandiant MD5 Indicator",`  
            `"description": "MD5 hash indicator from Mandiant data.",`  
            `"pattern": "[file:hashes.'MD5' = '2da4f427f42dd7798d262b58a4d629d0']",`  
            `"pattern_type": "stix",`  
            `"valid_from": "2023-05-03T04:19:10Z",`  
            `"labels": ["malicious-activity"],`  
            `"confidence": 100`  
        `}`  
    `]`  
`}`

