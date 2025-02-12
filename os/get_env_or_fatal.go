package os

import (
	"log"
	"os"
)

func GetEnvOrFatal(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		log.Fatal("Env " + key + "not found")
	}
	return value
}
