import subprocess
import json

def inspect_docker_metadata(image_name):
    try:
        output = subprocess.check_output(['docker', 'inspect', image_name], stderr=subprocess.DEVNULL)
        data = json.loads(output)[0]

        config = data.get("Config", {})
        labels = config.get("Labels", {})
        entrypoint = config.get("Entrypoint", [])
        cmd = config.get("Cmd", [])
        ports = list(config.get("ExposedPorts", {}).keys()) if config.get("ExposedPorts") else []

        return labels, entrypoint, cmd, ports
    except Exception as e:
        print(f"[WARN] docker inspect 실패: {e}")
        return {}, [], [], []

def infer_service_from_image(image_name: str) -> str:
    name = image_name.lower()

    # 1️⃣ 이름 기반 추론
    if "jenkins" in name:
        return "Jenkins"
    elif "tomcat" in name:
        return "Apache Tomcat"
    elif "nginx" in name:
        return "Nginx"
    elif "elasticsearch" in name:
        return "Elasticsearch"
    elif "redis" in name:
        return "Redis"
    elif "mysql" in name:
        return "MySQL"
    elif "postgres" in name:
        return "PostgreSQL"
    elif "mongo" in name:
        return "MongoDB"
    elif "consul" in name:
        return "Consul"
    elif "etcd" in name:
        return "etcd"

    # 2️⃣ docker inspect 기반 추론
    labels, entrypoint, cmd, ports = inspect_docker_metadata(image_name)

    combined = " ".join(entrypoint + cmd).lower()

    if "jenkins" in combined:
        return "Jenkins"
    elif "catalina" in combined or "tomcat" in combined:
        return "Apache Tomcat"
    elif "nginx" in combined:
        return "Nginx"
    elif "elasticsearch" in combined:
        return "Elasticsearch"
    elif "redis" in combined:
        return "Redis"
    elif "mysqld" in combined:
        return "MySQL"
    elif "postgres" in combined:
        return "PostgreSQL"
    elif "mongod" in combined:
        return "MongoDB"
    elif "consul" in combined:
        return "Consul"
    elif "etcd" in combined:
        return "etcd"

    # 3️⃣ 포트 기반 추론 (fallback)
    if "9200/tcp" in ports:
        return "Elasticsearch"
    elif "6379/tcp" in ports:
        return "Redis"
    elif "3306/tcp" in ports:
        return "MySQL"
    elif "27017/tcp" in ports:
        return "MongoDB"
    elif "5432/tcp" in ports:
        return "PostgreSQL"

    return "Unknown"
