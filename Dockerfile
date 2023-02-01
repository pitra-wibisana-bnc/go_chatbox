# base image
FROM golang:1.19-alpine 

# setup working directory
# /app
WORKDIR /app

# copy source to workdir
COPY . .

# validate package
RUN go mod tidy

# build golang apps to binary file
RUN go build -o binary main.go

# running binary file
CMD [ "/app/binary" ]