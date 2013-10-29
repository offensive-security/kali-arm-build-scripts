watch -n5 "ps -ef | grep mysqld | grep 101 | grep -v grep | awk '{print \$2}' | xargs kill -9"
