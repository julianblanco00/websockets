package main

import (
	"fmt"
	"websockets/websocket"
)

func main() {
	ws := websocket.Server(":8080")

	ws.OnError(func(e error) {
		fmt.Println("error: ", e)
	})

	ws.OnConnection(func(socket *websocket.Socket) {
		fmt.Println("connected to websocket server")
		socket.Send("hello from server!")
		socket.OnMessage(func(msg string) {
			fmt.Println("message received: ", msg)
		})
	})

	select {}
}
