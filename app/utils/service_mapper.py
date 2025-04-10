def infer_service_from_image(image_name: str) -> str:
    name = image_name.lower()
    keyword_map = {
        "jenkins": "Jenkins",
        "tomcat": "Apache Tomcat",
        "nginx": "Nginx",
        "elasticsearch": "Elasticsearch",
        "redis": "Redis",
        "mysql": "MySQL",
        "postgres": "PostgreSQL",
        "mongo": "MongoDB",
        "consul": "Consul",
        "etcd": "etcd",
        "httpd": "Apache HTTP Server",
        "apache": "Apache HTTP Server",
        "kibana": "Kibana",
        "grafana": "Grafana",
        "zookeeper": "Zookeeper",
        "rabbitmq": "RabbitMQ"
    }

    for keyword, service in keyword_map.items():
        if keyword in name:
            return service

    return "Unknown"
