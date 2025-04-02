package main

import (
	"github.com/SwanHtetAungPhyo/server_node/cmd"
	"github.com/SwanHtetAungPhyo/server_node/internal/config"
	"github.com/SwanHtetAungPhyo/server_node/pkg/utils"
	"github.com/gocql/gocql"
	"github.com/sirupsen/logrus"
	"time"
)

func main() {
	utils.Init()
	logger := utils.GetLogger()
	defer utils.RecoverFromPanic()
	loadConfig, err := config.LoadConfig(".")
	logger.Infof("Load config file %v", loadConfig)
	utils.FailOnErrorWithPanic(err, "load config fail")
	logger.WithFields(logrus.Fields{
		"config": loadConfig,
	})

	cmd.Start(loadConfig)

}

func CreateCassandraSession() (*gocql.Session, error) {
	cluster := gocql.NewCluster("127.0.0.1:9042", "127.0.0.1:9142")
	cluster.Keyspace = "test_keyspace"
	cluster.Consistency = gocql.Quorum
	cluster.ProtoVersion = 4
	cluster.NumConns = 5
	cluster.Timeout = 20 * time.Second
	cluster.PoolConfig.HostSelectionPolicy = gocql.DCAwareRoundRobinPolicy("datacenter1")
	cluster.Compressor = &gocql.SnappyCompressor{}

	session, err := cluster.CreateSession()
	if err != nil {
		return nil, err
	}
	return session, nil
}
