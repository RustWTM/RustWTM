//! Bounded incident snapshots: observed contributors, never inferred causality.
use crate::{Snapshot, control::ProcessRef};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub target: ProcessRef,
    pub cpu: f32,
    pub memory: u64,
    pub gpu: f32,
    pub io: f64,
    pub network: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub at: u64,
    pub cpu: f32,
    pub memory: u64,
    pub memory_total: u64,
    pub gpu: f32,
    pub network: f64,
    pub io: f64,
    pub processes: Vec<Process>,
    /// Per-process network attribution needs ETW; system adapter totals do not.
    #[serde(default)]
    pub process_network_available: bool,
    pub partial: bool,
}
impl Frame {
    pub fn of(s: &Snapshot, at: u64) -> Self {
        let rows: Vec<_> = s
            .processes
            .iter()
            .take(16384)
            .filter(|p| p.pid != 0)
            .collect();
        let clean32 = |v: f32| if v.is_finite() && v >= 0.0 { v } else { 0.0 };
        let mut chosen = std::collections::BTreeSet::new();
        for (metric, count) in [(0, 5), (1, 5), (2, 4), (3, 4), (4, 3)] {
            let mut indices: Vec<_> = (0..rows.len()).collect();
            let value = |index: usize| {
                let p = rows[index];
                match metric {
                    0 => f64::from(clean32(p.cpu_percent)),
                    1 => p.private_working_set as f64,
                    2 => p.io_rate(),
                    3 => p.net_rate(),
                    _ => f64::from(clean32(p.gpu_percent)),
                }
            };
            indices.sort_by(|a, b| {
                value(*b)
                    .total_cmp(&value(*a))
                    .then(rows[*a].pid.cmp(&rows[*b].pid))
            });
            chosen.extend(indices.into_iter().take(count));
        }
        let processes = chosen
            .into_iter()
            .map(|index| {
                let p = rows[index];
                let mut target = ProcessRef::from(p);
                target.name = target.name.chars().take(64).collect();
                Process {
                    target,
                    cpu: clean32(p.cpu_percent),
                    memory: p.private_working_set,
                    gpu: clean32(p.gpu_percent),
                    io: p.io_rate(),
                    network: p.net_rate(),
                }
            })
            .collect();
        let clean = |v: f64| if v.is_finite() && v >= 0.0 { v } else { 0.0 };
        Self {
            at,
            cpu: clean32(s.system.cpu_percent),
            memory: s.system.memory_used(),
            memory_total: s.system.memory_total,
            gpu: clean32(s.system.gpu_percent),
            network: clean(s.system.net_rx_rate) + clean(s.system.net_tx_rate),
            io: clean(s.system.io_read_rate) + clean(s.system.io_write_rate),
            processes,
            process_network_available: s.net_traced,
            partial: s.processes.len() > 16384,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedAction {
    pub at: u64,
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub level: String,
    pub message: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Replay {
    pub frames: Vec<Frame>,
    pub actions: Vec<RecordedAction>,
    pub actions_truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProcessInfo, SystemStats};
    #[test]
    fn contributor_union_is_bounded_and_preserves_distinct_resource_leaders() {
        let rows = (1..=24)
            .map(|pid| ProcessInfo {
                io: Default::default(),
                cycle_percent: 0.0,
                pid,
                parent_pid: 0,
                name: if pid == 1 {
                    "測".repeat(100)
                } else {
                    format!("app-{pid}.exe")
                },
                cpu_percent: if pid <= 5 { 50.0 } else { 0.0 },
                cpu_time: std::time::Duration::ZERO,
                working_set: 0,
                private_working_set: if (6..=10).contains(&pid) { 1000 } else { 0 },
                private_bytes: 0,
                thread_count: 1,
                handle_count: 1,
                session_id: 1,
                base_priority: 8,
                gpu_percent: if (19..=21).contains(&pid) { 50.0 } else { 0.0 },
                gpu_memory: 0,
                io_read_rate: if (11..=14).contains(&pid) {
                    1000.0
                } else {
                    0.0
                },
                io_write_rate: 0.0,
                net_rx_rate: if (15..=18).contains(&pid) {
                    1000.0
                } else {
                    0.0
                },
                net_tx_rate: 0.0,
                create_time: i64::from(pid) * 100,
                suspended: false,
                memory: Default::default(),
                gpu_detail: Default::default(),
            })
            .collect();
        let snapshot = Snapshot {
            processes: rows,
            system: SystemStats::default(),
            interval: Some(std::time::Duration::from_secs(1)),
            taken_at_ms: 5000,
            net_traced: true,
        };
        let frame = Frame::of(&snapshot, 5000);
        assert_eq!(frame.processes.len(), 21);
        for pid in 1..=21 {
            assert_eq!(
                frame
                    .processes
                    .iter()
                    .find(|p| p.target.pid == pid)
                    .unwrap()
                    .target
                    .create_time,
                i64::from(pid) * 100
            );
        }
        assert_eq!(frame.processes[0].target.name.chars().count(), 64);
        assert!(frame.process_network_available);
        assert!(!frame.partial);
        let bytes = serde_json::to_vec(&frame).unwrap();
        assert!(bytes.len() < 16384);
    }
    #[test]
    fn frame_of_ignores_non_finite_and_negative_rates() {
        let mut proc_info = ProcessInfo {
            io: Default::default(),
            cycle_percent: 0.0,
            pid: 42,
            parent_pid: 0,
            name: "worker.exe".into(),
            cpu_percent: 0.0,
            cpu_time: std::time::Duration::ZERO,
            working_set: 0,
            private_working_set: 0,
            private_bytes: 0,
            thread_count: 1,
            handle_count: 1,
            session_id: 1,
            base_priority: 8,
            gpu_percent: 0.0,
            gpu_memory: 0,
            io_read_rate: 30.0,
            io_write_rate: -5.0,
            net_rx_rate: f64::NEG_INFINITY,
            net_tx_rate: 12.0,
            create_time: 100,
            suspended: false,
            memory: Default::default(),
            gpu_detail: Default::default(),
        };
        let mut s = Snapshot {
            processes: vec![proc_info.clone()],
            system: SystemStats {
                io_read_rate: 100.0,
                io_write_rate: f64::NAN,
                net_rx_rate: f64::INFINITY,
                net_tx_rate: 42.0,
                ..Default::default()
            },
            interval: Some(std::time::Duration::from_secs(1)),
            taken_at_ms: 1000,
            net_traced: false,
        };

        let frame = Frame::of(&s, 1);
        assert_eq!(frame.io, 100.0);
        assert_eq!(frame.network, 42.0);
        assert_eq!(frame.processes[0].io, 30.0);
        assert_eq!(frame.processes[0].network, 12.0);

        s.system.io_read_rate = f64::NAN;
        s.system.net_tx_rate = -1.0;
        proc_info.io_read_rate = f64::NAN;
        s.processes = vec![proc_info];
        let frame_zero = Frame::of(&s, 2);
        assert_eq!(frame_zero.io, 0.0);
        assert_eq!(frame_zero.network, 0.0);
        assert_eq!(frame_zero.processes[0].io, 0.0);
    }

    #[test]
    fn frame_of_ignores_non_finite_and_negative_cpu_and_gpu() {
        let mk = |pid: u32, cpu: f32, gpu: f32| ProcessInfo {
            io: Default::default(),
            cycle_percent: 0.0,
            pid,
            parent_pid: 0,
            name: format!("p{pid}.exe"),
            cpu_percent: cpu,
            cpu_time: std::time::Duration::ZERO,
            working_set: 0,
            private_working_set: 0,
            private_bytes: 0,
            thread_count: 1,
            handle_count: 1,
            session_id: 1,
            base_priority: 8,
            gpu_percent: gpu,
            gpu_memory: 0,
            io_read_rate: 0.0,
            io_write_rate: 0.0,
            net_rx_rate: 0.0,
            net_tx_rate: 0.0,
            create_time: 100,
            suspended: false,
            memory: Default::default(),
            gpu_detail: Default::default(),
        };

        let s1 = Snapshot {
            processes: vec![
                mk(1, f32::NAN, f32::INFINITY),
                mk(2, -10.0, f32::NEG_INFINITY),
            ],
            system: SystemStats {
                cpu_percent: f32::NAN,
                gpu_percent: -5.0,
                ..Default::default()
            },
            interval: Some(std::time::Duration::from_secs(1)),
            taken_at_ms: 1000,
            net_traced: false,
        };
        let f1 = Frame::of(&s1, 1);
        assert_eq!(f1.cpu, 0.0);
        assert_eq!(f1.gpu, 0.0);
        assert!(f1.processes.iter().all(|p| p.cpu == 0.0 && p.gpu == 0.0));

        let mut procs: Vec<ProcessInfo> = (10..20).map(|pid| mk(pid, 10.0, 5.0)).collect();
        procs.push(mk(100, f32::NAN, f32::INFINITY));
        let s2 = Snapshot {
            processes: procs,
            system: SystemStats {
                cpu_percent: 60.0,
                gpu_percent: 25.0,
                ..Default::default()
            },
            interval: Some(std::time::Duration::from_secs(1)),
            taken_at_ms: 2000,
            net_traced: false,
        };
        let f2 = Frame::of(&s2, 2);
        assert_eq!(f2.cpu, 60.0);
        assert_eq!(f2.gpu, 25.0);
        assert!(!f2.processes.iter().any(|p| p.target.pid == 100));
    }
}
