# Use the official Node.js image
FROM node:16-alpine

# Set the working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the Next.js app
RUN npm run build

# Expose the port (Next.js default is 3000)
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
