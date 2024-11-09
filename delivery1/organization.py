class Organization:
    def __init__(self, manager):
        self.manager = manager
        self.list_documents = []

    def add_to_list(self,s):
        self.list_documents.append(s)
