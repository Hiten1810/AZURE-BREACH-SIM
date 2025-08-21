# Import the built‑in json module so we can pretty‑print query results
import json

# Import the CosmosClient class from the Azure SDK to interact with Cosmos DB
from azure.cosmos import CosmosClient

# Define a function that will connect to Cosmos DB and enumerate its contents
# Parameters:
#   url        - the Cosmos DB account endpoint (string)
#   credential - the access key or token for authentication (string)
def access_cosmos(url, credential):
    # Create a CosmosClient instance using the provided endpoint URL and credential
    client = CosmosClient(url, credential)

    # Loop over all databases in the Cosmos account
    for db in client.list_databases():
        # Print the database ID (name) to the console
        print(f"Database: {db['id']}")

        # Get a DatabaseProxy object for the current database using its ID
        database = client.get_database_client(db['id'])

        # Loop over all containers (collections) within the current database
        for container in database.list_containers():
            # Print the container ID (name) to the console, indented under the database
            print(f"  Container: {container['id']}")

            # Get a ContainerProxy object for the current container using its ID
            container_client = database.get_container_client(container['id'])

            # Query all items (documents) from this container
            #   "SELECT * FROM c" selects every record
            #   enable_cross_partition_query=True allows querying across all partitions
            for item in container_client.query_items(
                "SELECT * FROM c", enable_cross_partition_query=True
            ):
                # Print each item as JSON, formatted with indentation for readability
                print(json.dumps(item, indent=2))
