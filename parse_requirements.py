def parse_requirements(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines() if line.strip()]

dependencies = parse_requirements('requirements.txt')
print(dependencies)
