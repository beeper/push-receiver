package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	deflog "github.com/rs/zerolog/log"

	pr "github.com/beeper/push-receiver"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	deflog.Logger = deflog.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	defaultContextLogger := deflog.Logger.With().Bool("default_context_log", true).Caller().Logger()
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.DefaultContextLogger = &defaultContextLogger

	var (
		persistentIdFilename     string
		androidID, securityToken uint64
	)
	flag.NewFlagSet("help", flag.ExitOnError)
	flag.StringVar(&persistentIdFilename, "persistent-id", "persistent_id.txt", "PersistentID filename")
	flag.Uint64Var(&androidID, "android-id", 0, "Android ID")
	flag.Uint64Var(&securityToken, "security-token", 0, "Security token")
	flag.Parse()

	if androidID == 0 || securityToken == 0 {
		panic("androidID and securityToken must be set")
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	go realMain(ctx, &wg, androidID, securityToken, persistentIdFilename)

	<-done
	cancel()
	wg.Wait()
}

func realMain(ctx context.Context, wg *sync.WaitGroup, androidID, securityToken uint64, persistentIdFilename string) {
	wg.Add(1)
	defer wg.Done()

	creds := pr.GCMCredentials{
		AndroidID:     androidID,
		SecurityToken: securityToken,
	}

	logger := log.New(os.Stderr, "app : ", log.Lshortfile|log.Ldate|log.Ltime)

	// load received persistent ids
	persistentIDs, err := loadPersistentIDs(persistentIdFilename)
	if err != nil {
		logger.Fatal(err)
	}

	mcsClient := pr.New(
		pr.WithCreds(&creds),
		pr.WithHeartbeat(
			pr.WithServerInterval(1*time.Minute),
			pr.WithClientInterval(2*time.Minute),
			pr.WithAdaptive(true),
		),
		pr.WithReceivedPersistentID(persistentIDs),
	)

	go mcsClient.Listen(ctx)

	for event := range mcsClient.Events {
		switch ev := event.(type) {
		case *pr.ConnectedEvent:
			if err := clearPersistentID(persistentIdFilename); err != nil {
				logger.Fatal(err)
			}
		case *pr.UnauthorizedError:
			logger.Printf("error: %v", ev.ErrorObj)
		case *pr.HeartbeatError:
			logger.Printf("error: %v", ev.ErrorObj)
		case *pr.MessageEvent:
			logger.Printf("Received message: %s, %s", string(ev.RawData), ev.PersistentID)

			// save persistentID
			if err := savePersistentID(persistentIdFilename, ev.PersistentID); err != nil {
				logger.Fatal(err)
			}
		case *pr.RetryEvent:
			logger.Printf("retry : %v, %s", ev.ErrorObj, ev.RetryAfter)
		default:
			data, _ := json.Marshal(ev)
			logger.Printf("Event: %s (%s)", reflect.TypeOf(ev), data)
		}
	}
}

func isExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

func loadPersistentIDs(filename string) ([]string, error) {
	var persistentIDs []string

	if !isExist(filename) {
		return persistentIDs, nil
	}

	f, err := os.Open(filename)
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		return persistentIDs, err
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		persistentIDs = append(persistentIDs, scanner.Text())
	}
	return persistentIDs, nil
}

func savePersistentID(filename, persistentID string) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if f != nil {
		defer f.Close()
	}
	if err != nil {
		return err
	}
	_, err = f.WriteString(fmt.Sprintln(persistentID))
	return err
}

func clearPersistentID(filename string) error {
	if isExist(filename) {
		return os.Remove(filename)
	}
	return nil
}
