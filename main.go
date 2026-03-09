package cardpostechtest

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	types "github.com/DaevMithran/mini-hsm/hsm/v1"
	"github.com/DaevMithran/mini-hsm/services/keystore"
	"github.com/DaevMithran/mini-hsm/services/server"
	"github.com/DaevMithran/mini-hsm/services/storage"
	"google.golang.org/grpc"
)

func main() {
	masterKey := os.Getenv("HSM_MASTER_KEY")
	if masterKey == "" {
		log.Fatal("Missing env variable HSM_MASTER_KEY")
	}

	listenAddr := os.Getenv("HSM_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":26657"
	}

	stateFile := os.Getenv("HSM_PATH")
	if stateFile == "" {
		stateFile = "hsm.enc"
	}

	store := keystore.NewKeyStore()
	local := storage.LocalStore{Path: stateFile}
	backup, err := local.Load()
	if err == nil {
		store.Import(backup)
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	types.RegisterMsgServer(grpcServer, server.NewServer(store))
	types.RegisterQueryServer(grpcServer, server.NewServer(store))

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-shutdown

		backup, err := store.Export()
		if err != nil {
			log.Println("Failed to Export")
		}

		err = local.Save(backup)
		if err != nil {
			log.Println("Failed to Backup")
		}

		grpcServer.GracefulStop()
	}()

	log.Printf("server listening at %v", listener.Addr())
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
