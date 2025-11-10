from app.objects.secondclass.c_fact import Fact
from app.objects.secondclass.c_relationship import Relationship
from app.utility.base_parser import BaseParser


class Parser(BaseParser):
    """
    Parser for extracting Wazuh agent ID from client.keys file
    Used by BASTION plugin for Caldera-Wazuh agent correlation
    """

    def parse(self, blob):
        """
        Parse Wazuh agent ID from command output

        Expected input format from client.keys:
        "001 VM1-Ubuntu any KEY..."

        This parser extracts the first field (agent ID)
        """
        relationships = []

        for match in self.line(blob):
            # Skip empty lines or "NONE" (when client.keys doesn't exist)
            if not match or match.strip() == "NONE":
                continue

            # Extract agent ID (should be numeric like "001", "002", etc.)
            agent_id = match.strip()

            # Validate it's a valid agent ID (numeric)
            if agent_id.isdigit():
                for mp in self.mappers:
                    # Create fact with wazuh.agent.id trait
                    source = self.set_value(mp.source, agent_id, self.used_facts)
                    relationships.append(
                        Relationship(
                            source=Fact(mp.source, source),
                            edge=mp.edge,
                            target=Fact(mp.target, agent_id)
                        )
                    )

        return relationships
