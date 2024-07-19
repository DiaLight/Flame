import enum


class Kind(enum.Enum):
  VA32 = 0
  REL32 = 1
  NOT_VA32 = 2

  @staticmethod
  def parse(val):
    if val == '!VA32':
      return Kind.NOT_VA32
    if val == 'VA32':
      return Kind.VA32
    if val == 'REL32':
      return Kind.REL32
    return None

  def format(self):
    if self is Kind.NOT_VA32:
      return '!VA32'
    if self.name == 'NOT_VA32':
      return '!VA32'
    return self.name

  def is_ignore(self):
    return self is Kind.NOT_VA32
