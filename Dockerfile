# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install additional tools
RUN apt-get update && \
    apt-get install -y nmap gobuster ffuf sqlmap && \
    apt-get clean

# Make port 8501 available to the world outside this container
EXPOSE 8501

# Run streamlit app when the container launches
CMD ["python3", "main.py", "--streamlit"]
