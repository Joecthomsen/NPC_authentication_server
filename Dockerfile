FROM node:18

#ENV DB_USER=root
#ENV DB_PASSWORD=example
#ENV HOST=127.0.0.1
#ENV HOST=mongo
#ENV DB_PORT=27017
#ENV SERVER_PORT=8080

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./

RUN npm install
# RUN touch /usr/src/app/.env
# RUN echo "DB_USER=$DB_USER" >> /usr/src/app/.env
# RUN echo "DB_PASSWORD=$DB_PASSWORD" >> /usr/src/app/.env
# RUN echo "HOST=$HOST" >> /usr/src/app/.env
# RUN echo "DB_PORT=$DB_PORT" >> /usr/src/app/.env
# RUN echo "SERVER_PORT=$SERVER_PORT" >> /usr/src/app/.env
# RUN echo "ACCESS_TOKEN_KEY=secret" >> /usr/src/app/.env
# If you are building your code for production
#RUN npm ci --omit=dev

# Bundle app source
COPY . .

EXPOSE 9090
CMD [ "node", "bin/www" ]