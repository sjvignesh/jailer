use clap::{Arg, App};
use std::{fs, io::{self, Write}, path::Path};
use std::process::{self, Command};
use std::os::unix::fs as unix_fs;
use std::os::unix::process::CommandExt;
use nix::unistd;
use nix::sched::{self, CloneFlags}; 

const ROOT: &str = "/";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const MOUNT_POINT: &str = "/tmp/sandcastle";
const JAILER_FS: &str = "/home/local/ZOHOCORP/vignesh-pt3767/template";

fn main() {
    let arguments = App::new("Sandcastle")
        .version("0.1")
        .author("Vigneshwar S <vigneshwar.sm@zohocorp.com>")
        .arg(Arg::with_name("id")
            .short("i")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("target")
            .short("t")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("quota")
            .short("q")
            .takes_value(true))
        .arg(Arg::with_name("share")
            .short("s")
            .takes_value(true))
        .arg(Arg::with_name("limit")
            .short("l")
            .takes_value(true))
        .arg(Arg::with_name("cpuset")
            .short("c")
            .takes_value(true))
        .arg(Arg::with_name("memset")
            .short("m")
            .takes_value(true))
        .arg(Arg::with_name("mountns")
            .short("M"))
        .arg(Arg::with_name("utsns")
            .short("u"))
        .arg(Arg::with_name("userns")
            .short("U"))
        .get_matches();
    
    let id = arguments.value_of("id").unwrap();
    let target = arguments.value_of("target").unwrap();
    let quota = arguments.value_of("quota").unwrap();
    let share = arguments.value_of("share").unwrap();
    let limit = arguments.value_of("limit").unwrap();
    let cpuset = arguments.value_of("cpuset").unwrap();
    let memset = arguments.value_of("memset").unwrap();

    let mut ns_flags = CloneFlags::empty();
    if arguments.is_present("mountns") { ns_flags.set(CloneFlags::CLONE_NEWNS, true) }
    if arguments.is_present("utsns") { ns_flags.set(CloneFlags::CLONE_NEWUTS, true) }
    if arguments.is_present("userns") { ns_flags.set(CloneFlags::CLONE_NEWUSER, true) }
    
    let new_root = format!("{}/{}", MOUNT_POINT, id);
    fs::create_dir(&new_root).unwrap();

    let mut config = fs::File::create(&format!("{}/config", new_root)[..]).unwrap();
    config.write(target.as_bytes()).unwrap();

    copy_dir_all(JAILER_FS, &new_root).unwrap();
    fs::copy(target, format!("{}/main", &new_root)).unwrap();

    set_cgroup_cpu(id, quota, share).unwrap();
    set_cgroup_pids(id, limit).unwrap();
    set_cgroup_cpuset(id, cpuset, memset).unwrap();
    set_cgroup_cpuacct(id).unwrap();

    sched::unshare(ns_flags).unwrap();

    unistd::chroot(&new_root[..]).unwrap();

    std::env::set_current_dir(ROOT).unwrap();

    Command::new("./main").exec();  

    clean_cgroups(id).unwrap();
}

fn copy_dir_all(from: impl AsRef<Path>, to: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&to)?;
    for entry in fs::read_dir(from)? {
        match entry {
            Ok(node) => {
                let file_type = node.file_type()?;
                if file_type.is_dir() {
                    copy_dir_all(node.path(), to.as_ref().join(node.file_name()))?;
                }
                
                if file_type.is_file() {
                    fs::copy(node.path(), to.as_ref().join(node.file_name()))?;
                }

                if file_type.is_symlink() {
                    unix_fs::symlink(fs::read_link(node.path()).unwrap(), 
                                        to.as_ref().join(node.file_name()))?;
                }
            },
            Err(_) => panic!("Problem reading jail template")
        };
    }

    Ok(())
}

fn set_cgroup_cpu(process_id: &str, quota: &str, share: &str) -> Result<(), io::Error> {
    let path = format!("{}/cpu/sandcastle/{}", CGROUP_ROOT, process_id);
    fs::create_dir_all(&path)?;    

    write_special(&format!("{}/cpu.cfs_quota_us", path), &quota.to_string())?;
    write_special(&format!("{}/cpu.shares", path), &share.to_string())?;

    write_special(&format!("{}/tasks", path), &process::id().to_string())?;

    Ok(())
}

fn set_cgroup_pids(process_id: &str, limit: &str) -> Result<(), io::Error> {
    let path = format!("{}/pids/sandcastle/{}", CGROUP_ROOT, process_id);
    fs::create_dir_all(&path)?;   

    write_special(&format!("{}/pids.max", path), &limit.to_string())?;

    write_special(&format!("{}/tasks", path), &process::id().to_string())?;

    Ok(())
}

fn set_cgroup_cpuset(process_id: &str, cpuset: &str, memset: &str) -> Result<(), io::Error> {
    let path = format!("{}/cpuset/sandcastle/{}", CGROUP_ROOT, process_id);
    fs::create_dir_all(&path).unwrap();    

    // let mut mems_file = fs::OpenOptions::new().append(true)
    //                         .open(format!("{}/cpuset.mems", path))
    //                         .expect("Failed to read cpuset.mems in cgroup");

    // mems_file.write(memset.as_bytes()).expect("Failed to write cpuset.mems in cgroup");

    write_special(&format!("{}/cpuset.mems", path), &memset.to_string()).expect("mems failed");
    
    // let mut cpus_file = fs::OpenOptions::new().append(true)
    //                         .open(format!("{}/cpuset.cpus", path))
    //                         .expect("Failed to read cpuset.cpus in cgroup");

    // cpus_file.write(cpuset.as_bytes()).expect("Failed to write cpuset.cpus in cgroup");

    write_special(&format!("{}/cpuset.cpus", path), &cpuset.to_string()).expect("cpus failed");

    // let mut tasks_file = fs::OpenOptions::new().append(true)
    //                         .open(format!("{}/tasks", path))
    //                         .expect("Failed to read tasks in cgroup");

    // tasks_file.write(process::id().to_string().as_bytes()).expect("Failed to write tasks in cgroup");

    write_special(&format!("{}/tasks", path), &process::id().to_string())?;

    Ok(())
}

fn set_cgroup_cpuacct(process_id: &str) -> Result<(), io::Error> {
    let path = format!("{}/cpuacct/sandcastle/{}", CGROUP_ROOT, process_id);
    fs::create_dir_all(&path)?;  
    
    write_special(&format!("{}/tasks", path), &process::id().to_string())?;

    Ok(())
}

fn clean_cgroups(process_id: &str) -> Result<(), io::Error> {
    delete_file(&format!("{}/cpu/sandcastle/{}", CGROUP_ROOT, process_id))?;
    delete_file(&format!("{}/pids/sandcastle/{}", CGROUP_ROOT, process_id))?;
    delete_file(&format!("{}/cpuset/sandcastle/{}", CGROUP_ROOT, process_id))?;
    delete_file(&format!("{}/cpuacct/sandcastle/{}", CGROUP_ROOT, process_id))?;

    Ok(())
}

fn write_special(file: &String, data: &String) -> Result<(), io::Error> {
    let mut file = fs::OpenOptions::new().append(true).open(&file[..])?;
    file.write(data.trim().as_bytes())?;

    Ok(())
}

fn delete_file(file: &String) -> Result<(), io::Error> {
    fs::remove_dir(file)?;  

    Ok(())
}