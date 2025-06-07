# Use the official Python image as the base image
FROM python:3.8-slim

# Set the working directory
WORKDIR /usr/src/app

# Copy the requirements file
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Start the Python engine
CMD ["python", "app/engine/facade.py"]
