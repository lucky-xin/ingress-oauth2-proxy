//Copyright © 2024 chaoxin.lu
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package svc

import (
	"context"
	"errors"
	"github.com/lucky-xin/xyz-common-go/env"
	"github.com/redis/go-redis/v9"
	"log"
	"strings"
)

func CreateRedis() (redis.UniversalClient, error) {
	rt := env.GetString("REDIS_TYPE", "STANDALONE")
	nodes := env.GetStringArray("REDIS_NODES", []string{"gzv-dev-redis-1.xyz.com:6379"})
	user := env.GetString("REDIS_USER", "")
	pwd := env.GetString("REDIS_PWD", "xxx")
	db := env.GetInt("REDIS_DB", 3)
	cliName := env.GetString("REDIS_CLI_NAME", "ingress-oauth2-proxy")
	if rt == "STANDALONE" {
		return redis.NewClient(
			&redis.Options{
				Addr:     nodes[0],
				Username: user,
				Password: pwd,
				DB:       db,
			}), nil
	} else if rt == "CLUSTER" {
		cli := redis.NewClusterClient(
			&redis.ClusterOptions{
				Addrs:      nodes,
				Username:   user,
				Password:   pwd,
				ClientName: cliName,
			})
		lineText, err := cli.ClusterNodes(context.Background()).Result()
		if err != nil {
			return nil, err
		}
		//969cd951afe67329683587d34d8387c252e202b1 172.28.122.180:6379@16379 slave 4d013194626ded75b6d4bf708e5b36f1f5159658 0 1693817889577 2 connected
		var clusterNodes []string
		for _, line := range strings.Split(lineText, "\n") {
			splits := strings.Split(line, " ")
			if len(splits) < 2 {
				continue
			}
			clusterNodes = append(clusterNodes, strings.Split(splits[1], "@")[0])
		}
		log.Println(strings.Join(clusterNodes, ","))
		return redis.NewClusterClient(
			&redis.ClusterOptions{
				Addrs:      clusterNodes,
				Username:   user,
				Password:   pwd,
				ClientName: cliName,
			}), nil
	}
	return nil, errors.New("unsupported redis type:" + rt)
}
