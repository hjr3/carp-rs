#!/bin/bash
SESSION=carp

tmux -2 new-session -d -s $SESSION
tmux bind-key -n C-c kill-session
tmux bind-key -n C-d kill-session
tmux bind-key -n Escape kill-session

tmux new-window -t $SESSION:1 -n 'CARP'
tmux split-window -v
tmux select-pane -t 0
tmux send-keys "sudo /vagrant/target/debug/examples/basic -i eth1 -s 10.0.2.30" C-m
tmux select-pane -t 1
tmux send-keys "sudo RUST_LOG=trace /vagrant/target/debug/examples/pure -i eth1 -s 10.0.2.40" C-m

# Attach to session
tmux -2 attach-session -t $SESSION
