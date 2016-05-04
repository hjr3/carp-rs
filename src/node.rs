// Copyright (c) 2016  Herman J. Radtke III <herman@hermanradtke.com>
//
// This file is part of carp-rs.
//
// carp-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// carp-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with carp-rs.  If not, see <http://www.gnu.org/licenses/>.

use std::cmp::Ordering;
use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum Role {
    Primary,
    Backup,
}

/// Whether to become a primary node as soon as possible
#[derive(Debug, Eq, PartialEq)]
pub enum Alignment {
    Passive,
    Aggressive,
}

/// A CARP node
///
/// The node can be local or remote
#[derive(Debug, Eq, PartialEq)]
pub struct Node {
    /// Role of the node
    pub role: Role,

    /// Advertisement frequency
    ///
    /// Lower is more frequent
    pub adv_freq: Duration,

    /// IP address of the node
    ///
    /// This is used to break ties when determine roles
    pub ip: IpAddr,
}

impl Node {
    pub fn new(role: Role, adv_freq: Duration, ip: IpAddr) -> Node {
        Node {
            role: role,
            adv_freq: adv_freq,
            ip: ip,
        }
    }

    /// Compare another node to determine if a role change is required
    ///
    /// A passive node will only become primary when another primary node times out
    pub fn role_change(&self, other: &Self, alignment: Alignment) -> Role {
        match self.role {
            Role::Primary => {
                if self > other {
                    Role::Backup
                } else {
                    Role::Primary
                }
            }
            Role::Backup => {
                if alignment == Alignment::Aggressive && self < other {
                    Role::Primary
                } else {
                    Role::Backup
                }
            }
        }
    }
}

impl PartialOrd for Node {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.adv_freq == other.adv_freq {
            Some(match self.ip.cmp(&other.ip) {
                Ordering::Less => Ordering::Greater,
                Ordering::Greater => Ordering::Less,
                Ordering::Equal => Ordering::Less,
            })

        } else {
            Some(self.adv_freq.cmp(&other.adv_freq))
        }
    }
}

impl Ord for Node {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_primary_to_backup() {
        let node = Node::new(Role::Primary,
                             Duration::from_secs(2),
                             "10.0.0.2".parse().unwrap());
        let other = Node::new(Role::Primary,
                              Duration::from_secs(1),
                              "10.0.0.1".parse().unwrap());

        assert_eq!(Role::Backup, node.role_change(&other, Alignment::Passive));

        let node = Node::new(Role::Primary,
                             Duration::from_secs(1),
                             "10.0.0.2".parse().unwrap());
        let other = Node::new(Role::Primary,
                              Duration::from_secs(1),
                              "10.0.0.1".parse().unwrap());

        assert_eq!(Role::Primary, node.role_change(&other, Alignment::Passive));

        let node = Node::new(Role::Primary,
                             Duration::from_secs(1),
                             "10.0.0.1".parse().unwrap());
        let other = Node::new(Role::Primary,
                              Duration::from_secs(1),
                              "10.0.0.2".parse().unwrap());

        assert_eq!(Role::Backup, node.role_change(&other, Alignment::Passive));
    }

    #[test]
    fn test_backup_to_primary() {
        let node = Node::new(Role::Backup,
                             Duration::from_secs(1),
                             "10.0.0.1".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(2),
                              "10.0.0.2".parse().unwrap());

        assert_eq!(Role::Primary,
                   node.role_change(&other, Alignment::Aggressive));

        let node = Node::new(Role::Backup,
                             Duration::from_secs(1),
                             "10.0.0.2".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(1),
                              "10.0.0.1".parse().unwrap());

        assert_eq!(Role::Primary,
                   node.role_change(&other, Alignment::Aggressive));
    }

    #[test]
    fn test_backup_non_aggressive() {
        let node = Node::new(Role::Backup,
                             Duration::from_secs(1),
                             "10.0.0.1".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(2),
                              "10.0.0.2".parse().unwrap());

        assert_eq!(Role::Backup, node.role_change(&other, Alignment::Passive));
    }

    #[test]
    fn test_cmp_less() {
        let node = Node::new(Role::Backup,
                             Duration::from_secs(1),
                             "10.0.0.2".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(2),
                              "10.0.0.1".parse().unwrap());
        let given = node.cmp(&other);
        assert_eq!(Ordering::Less, given);

        let node = Node::new(Role::Backup,
                             Duration::from_secs(1),
                             "10.0.0.2".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(1),
                              "10.0.0.1".parse().unwrap());
        let given = node.cmp(&other);
        assert_eq!(Ordering::Less, given);
    }

    #[test]
    fn test_cmp_greater() {
        let node = Node::new(Role::Backup,
                             Duration::from_secs(2),
                             "10.0.0.1".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(1),
                              "10.0.0.2".parse().unwrap());
        let given = node.cmp(&other);
        assert_eq!(Ordering::Greater, given);

        let node = Node::new(Role::Backup,
                             Duration::from_secs(1),
                             "10.0.0.1".parse().unwrap());
        let other = Node::new(Role::Backup,
                              Duration::from_secs(1),
                              "10.0.0.2".parse().unwrap());
        let given = node.cmp(&other);
        assert_eq!(Ordering::Greater, given);
    }
}
