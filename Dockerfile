# Use an official Python runtime as a parent image
FROM python:3.8-alpine

# Give the container a name
LABEL NAME = "CxOne Scan Monster"

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir requests urllib3

# Define entrypoint
ENTRYPOINT ["python", "./scan_monster.py"]