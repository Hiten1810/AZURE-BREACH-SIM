# Import the BlobServiceClient class from Azure's storage SDK
# This is the main entry point for interacting with blob storage accounts
from azure.storage.blob import BlobServiceClient

def access_blob(conn_str):
    """
    Connect to an Azure Blob Storage account using its connection string,
    loop through all containers, and print the full URL for any image blobs.
    """

    try:
        # Create a service-level client object from the connection string
        # This gives us authenticated access to the whole storage account
        service = BlobServiceClient.from_connection_string(conn_str)

        # Extract just the account name from the client (for building URLs later)
        account_name = service.account_name

        # Let the user know we’ve connected successfully
        print(f"Connected to storage account: {account_name}")

        # Loop over every container (bucket) in the storage account
        for container in service.list_containers():
            # Pull the container's name from its metadata
            container_name = container['name']

            # Print the container name so we know which one we're looking at
            print(f"Container: {container_name}")

            # Create a client scoped to this specific container
            container_client = service.get_container_client(container_name)

            # Loop over every blob (file) inside the current container
            for blob in container_client.list_blobs():
                # Check the blob's content type (MIME type) to see if it's an image
                if blob.content_settings.content_type and blob.content_settings.content_type.startswith("image/"):
                    # Build the full HTTPS URL for this blob using the known Azure format
                    blob_url = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob.name}"

                    # Print the URL so it can be visited or logged
                    print(f"  Image URL: {blob_url}")

        # If we reach this point, all containers/blobs have been processed without error

    except Exception as e:
        # If anything goes wrong (bad key, network issue, etc.), print an error message
        print(f"[ERROR] Blob access failed: {e}")
