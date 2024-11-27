# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Make port 5000 available to the world outside this container
# EXPOSE 80

# Define environment variable
# ENV FLASK_APP=app.py

# Run the application
# CMD ["flask", "run", "--host=0.0.0.0", "--port=80"]
CMD flask run --host=0.0.0.0 --port=80 --debug --reload
# CMD python -m bottle --debug --reload --server paste --bind 0.0.0.0:80 app:application
