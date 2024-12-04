import os
import json
import uuid
import logging
from stix2 import Indicator, Campaign, ThreatActor, Malware, Report, Bundle

# Directory setup
RESPONSE_DIR = "./responses"
OUTPUT_DIR = "./stix_outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Base Processor Class
class BaseProcessor:
    def process(self, data):
        """
        Abstract method to process data into a STIX 2.1 Bundle.
        """
        raise NotImplementedError("Subclasses must implement the `process` method.")

# Mandiant MD5 Processor
class MandiantMD5Processor(BaseProcessor):
    def process(self, data):
        logger.debug("Processing Mandiant MD5 data")
        id_field = data.get("id")
        value_field = data.get("value")
        mscore = data.get("mscore")

        if not id_field or not value_field or mscore is None:
            raise KeyError("Missing required fields in Mandiant MD5 data.")

        indicator = Indicator(
            id=f"indicator--{id_field.split('--')[1]}",
            name="Mandiant MD5 Indicator",
            description="MD5 hash indicator from Mandiant data.",
            pattern=f"[file:hashes.'MD5' = '{value_field}']",
            pattern_type="stix",
            valid_from=data.get("first_seen", "2023-01-01T00:00:00Z"),
            confidence=mscore,
            labels=["malicious-activity"]
        )
        return Bundle(objects=[indicator])

# Mandiant Malware Processor
class MandiantMalwareProcessor(BaseProcessor):
    def process(self, data):
        logger.debug("Processing Mandiant Malware data")
        id_field = data.get("id")
        name_field = data.get("name", "Unnamed Malware")
        description = data.get("description", "No description provided.")
        associated_hashes = data.get("associated_hashes", [])
        attributed_associations = data.get("attributed_associations", [])
        campaigns = data.get("campaigns", [])
        reports = data.get("reports", [])

        if not id_field:
            raise KeyError("Missing required fields in Mandiant Malware data.")

        malware = Malware(
            id=f"malware--{id_field.split('--')[1]}",
            name=name_field,
            description=description,
            is_family=False
        )

        hash_indicators = [
            Indicator(
                id=f"indicator--{uuid.uuid4()}",
                name=f"Associated Hash: {assoc_hash['value']}",
                description=f"Hash of type {assoc_hash['type']} associated with malware.",
                pattern=f"[file:hashes.'{assoc_hash['type'].upper()}' = '{assoc_hash['value']}']",
                pattern_type="stix",
                valid_from=data.get("first_seen", "2023-01-01T00:00:00Z"),
                confidence=50,
                labels=["malware", "associated-hash"]
            )
            for assoc_hash in associated_hashes
        ]

        threat_actors = [
            ThreatActor(
                id=assoc.get("id"),
                name=assoc.get("name"),
                description=f"Threat actor associated: {assoc.get('name')}"
            )
            for assoc in attributed_associations if assoc.get("type") == "threat-actor"
        ]

        campaign_objects = [
            Campaign(
                id=campaign["id"],
                name=campaign["name"],
                description=campaign.get("title", "No description provided.")
            )
            for campaign in campaigns
        ]

        report_objects = [
            Report(
                id=f"report--{uuid.uuid4()}",
                name=report["title"],
                description=f"Report: {report['title']}",
                published=report["published_date"],
                object_refs=[malware.id] + [ind.id for ind in hash_indicators]
            )
            for report in reports
        ]

        bundle_objects = [malware] + hash_indicators + threat_actors + campaign_objects + report_objects
        return Bundle(objects=bundle_objects)

# Recorded Future Processor
class RecordedFutureProcessor(BaseProcessor):
    def process(self, data):
        logger.debug("Processing Recorded Future data")
        raw_data = data.get("raw_data", {})
        entity = raw_data.get("entity", {})
        risk = raw_data.get("risk", {})
        timestamps = raw_data.get("timestamps", {})
        evidence_details = risk.get("evidenceDetails", [])

        id_field = entity.get("id")
        name_field = entity.get("name", "Unnamed Entity")
        score = risk.get("score")
        criticality_label = risk.get("criticalityLabel", "unknown").lower()
        first_seen = timestamps.get("firstSeen", "2023-01-01T00:00:00Z")
        description = risk.get("riskSummary", "No risk summary provided.")
        hash_algorithm = raw_data.get("hashAlgorithm", "MD5").upper()

        if not id_field or not name_field or score is None:
            raise KeyError("Missing required fields in Recorded Future data.")

        pattern = f"[file:hashes.'{hash_algorithm}' = '{name_field}']"
        indicator = Indicator(
            id=f"indicator--{uuid.uuid4()}",
            name=f"Recorded Future Indicator: {name_field}",
            description=description,
            pattern=pattern,
            pattern_type="stix",
            valid_from=first_seen,
            confidence=score,
            labels=["malicious-activity", criticality_label]
        )

        reports = [
            Report(
                id=f"report--{uuid.uuid4()}",
                name=evidence.get("rule", "Unnamed Rule"),
                description=evidence.get("evidenceString", "No evidence provided."),
                published=evidence.get("timestamp", first_seen),
                object_refs=[indicator.id]
            )
            for evidence in evidence_details
        ]

        return Bundle(objects=[indicator] + reports)

# Manager Class
class STIXConverter:
    PROCESSORS = {
        "malware": MandiantMalwareProcessor,
        "md5": MandiantMD5Processor,
        "recorded": RecordedFutureProcessor
    }

    @staticmethod
    def determine_processor(file_name):
        for key, processor in STIXConverter.PROCESSORS.items():
            if key in file_name.lower():
                return processor()
        return None

    def convert_file(self, file_path):
        try:
            logger.info(f"Reading file: {file_path}")
            with open(file_path, "r") as file:
                data = json.load(file)

            processor = self.determine_processor(file_path)
            if processor:
                stix_bundle = processor.process(data)
                output_file = os.path.join(OUTPUT_DIR, f"{os.path.basename(file_path)}.stix.json")
                with open(output_file, "w") as out_file:
                    out_file.write(stix_bundle.serialize(pretty=True))
                logger.info(f"Converted and saved: {output_file}")
            else:
                logger.warning(f"Unsupported file: {file_path}")
        except Exception as e:
            logger.exception(f"Error processing file {file_path}")

    def process_all_files(self, directory):
        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)
            if file_name.endswith(".json"):
                self.convert_file(file_path)

# Main Execution
if __name__ == "__main__":
    converter = STIXConverter()
    converter.process_all_files(RESPONSE_DIR)
