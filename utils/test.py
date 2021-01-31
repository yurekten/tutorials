import subprocess
from run_exercise import ExerciseRunner


if __name__ == '__main__':

    #sys.path.append("/usr/local/lib/python2.7/dist-packages")
    # from mininet.log import setLogLevel
    # setLogLevel("info")

    topo = "config/topology.json"
    behavioral_exe = "simple_switch_grpc"
    quiet = False
    build_dir = "build"
    log_dir = "logs"
    pcap_dir = "pcaps"
    file_name_base = "sfc"
    file_name = file_name_base + ".p4"
    runtime_file_name = build_dir + "/" + file_name + ".p4info.txt"
    switch_json = "build/"+ file_name_base +".json"
    subprocess.call(["rm", "-rf", log_dir, pcap_dir, build_dir])
    subprocess.call(["mkdir", "-p", log_dir, pcap_dir, build_dir])
    subprocess.call(["p4c-bm2-ss", "--p4v", "16", "--p4runtime-files", runtime_file_name, "-o", switch_json, file_name])


    #args = get_args()
    exercise = ExerciseRunner(topo, log_dir, pcap_dir,
                              switch_json, behavioral_exe, quiet)

    exercise.run_exercise()
