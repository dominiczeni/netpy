# Use the official slim Python 3 image as the base
FROM python:3-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY ./src/requirements.txt .

# Set environment variables
ENV UN1=''
ENV PW1=''
ENV UN2=''
ENV PW2=''
ENV UN3=''
ENV PW3=''
ENV UN4=''
ENV PW4=''
ENV JB1_TYPE=''
ENV JB1_HOST=''
ENV JB1_USER=''
ENV JB1_PASS=''
ENV JB1_SECRET=''
ENV JB1_PORT=''

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# Install openssh client for manual troubleshooting/verifying basic SSH connectivity.
RUN apt-get update && apt-get install -y openssh-client
# Copy the rest of the application code
COPY . .

# If your application has a specific command to run, specify it here
CMD ["bash"]
