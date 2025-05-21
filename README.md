# Authorizations Management for Agentspace

This project provides a simple web-based user interface (built with NiceGUI) to help you create and manage OAuth Authorizations within a Google Cloud Project for use with Agentspace custom agents.

It leverages Google Cloud Application Default Credentials (ADC) to authenticate with the Google Cloud APIs (specifically the Discovery Engine API `v1alpha` for Authorizations and Cloud Resource Manager API for project number lookup).

## Features

- Create new Agentspace (Discovery Engine) Authorizations by providing OAuth client details.
- Delete existing Agentspace (Discovery Engine) Authorizations.
- Uses Application Default Credentials (ADC) for authentication.
- Provides a simple, intuitive web interface.
- Logs activity to a local file (`activity.log.YYYY-MM-DD`).

## Prerequisites

1.  **Python 3.12+**: Ensure you have Python installed. May work with earlier versions of Python
2.  **Google Cloud Project**: You need an active Google Cloud Project.
3.  **Application Default Credentials (ADC)**: The script authenticates using ADC. Make sure your environment is set up to provide these credentials. This typically involves:
    *   Running `gcloud auth application-default login` on your local machine.
    *   Or, setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable pointing to a service account key file (less recommended for local development).
    *   Or, running the script on a GCP resource (like GCE, GKE, Cloud Run, etc.) with an attached service account that has the necessary permissions.
4.  **Required Permissions**: The credentials used must have permissions to:
    *   Read project information (e.g., `resourcemanager.projects.get`).
    *   Manage Discovery Engine Authorizations (e.g., `discoveryengine.authorizations.create`, `discoveryengine.authorizations.delete`). The `roles/discoveryengine.admin` or a custom role with these specific permissions should suffice.

## Installation

Clone the repository and install the required Python packages:

```bash
pip install -r requirements.txt # (Assuming you create a requirements.txt)
# OR manually install:
# pip install requests google-auth google-api-python-client python-dotenv nicegui
```
*(Note: A `requirements.txt` file is recommended for managing dependencies)*

## Configuration

The script requires your Google Cloud Project ID. You can provide this in two ways:

1.  **Environment Variable**: Set the `GOOGLE_CLOUD_PROJECT` environment variable before running the script.
2.  **.env file**: Create a file named `.env` in the same directory as `webui_as_authentication.py` and add the following line:

    ```dotenv
    GOOGLE_CLOUD_PROJECT=your-gcp-project-id
    ```

    Replace `your-gcp-project-id` with your actual GCP project ID. The script uses `python-dotenv` to load this file automatically.

## How to Run

Once prerequisites are met and dependencies are installed, run the script:

```bash
python as_authentication_manager.py
```

The web UI will start, typically accessible at `http://localhost:8081`. Open this URL in your web browser.

## Usage

1.  Enter your GCP Project ID in the configuration section (this field might be pre-filled if set via `.env` or environment variable).
2.  Navigate between the "Create Authorization" and "Delete Authorization" tabs.
3.  Currently, the user must remember/track the authorization id(s) they have created, if they wish to delete them later. There is no GET or `list` method(s) for Authorizations as of 21 May 2025.
3.  Fill in the required details for the desired action and click the corresponding button.
4.  Status and results will be displayed in the status area below the buttons.
5.  Check `activity.log` in the script's directory for detailed logs of API calls and responses.