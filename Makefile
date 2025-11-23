APP_CLIENT=vpn-client-simple
APP_SERVER=vpn-server-simple

SRC=main.go

.PHONY: client server clean

client:
	go build -o $(APP_CLIENT) $(SRC)

server:
	go build -o $(APP_SERVER) $(SRC)

clean:
	rm -f $(APP_CLIENT) $(APP_SERVER)
