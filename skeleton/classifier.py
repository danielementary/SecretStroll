
from torch import optim


class Basic_Net(nn.Module):
    def __init__(self):
        super(Basic_Net, self).__init__()
        nb_hidden = 200
        self.conv1 = nn.Conv1d(1, 32, kernel_size=5)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3)
        self.fc1 = nn.Linear(9 * 64, nb_hidden)
        self.fc2 = nn.Linear(nb_hidden, 100)

    def forward(self, x):
        x = F.relu(F.max_pool2d(self.conv1(x), kernel_size = 2))
        x = F.relu(self.conv2(x))
        x = F.relu(self.fc1(x.view(-1, 9 * 64)))
        x = self.fc2(x)
        return x

def train_model(model, input, target, mini_batch_size, eta):
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr = eta)
    sum_loss = 0
    for b in range(0, input.size(0), mini_batch_size):
        output = model(input.narrow(0, b, mini_batch_size))

        optimizer.zero_grad()
        loss = criterion(output, target.narrow(0, b, mini_batch_size))
        sum_loss = sum_loss + loss.item()
        loss.backward()
        optimizer.step()

    return sum_loss
    
def compute_nb_errors(model, input, target, mini_batch_size):
    tot_errors = 0
    for b in range(0, input.size(0), mini_batch_size):
        output = model(input.narrow(0, b, mini_batch_size))
        _, index_out = torch.max(output,1)
        
        errors = (index_out != target.narrow(0, b, mini_batch_size))
        tot_errors += errors.sum().item()

    return tot_errors

#Evaluate a model, with one loss
def eval_model(model, train_input, train_target,test_input, test_target, mini_batch_size, eta):
    print(model)
    print("TRAINING")
    print("EPOCH : TOT_LOSS : OUTPUT : ERROR RATE")
    for e in range(0, 25):
        sum_loss = train_model(model, train_input, train_target, mini_batch_size, eta)
        tot_err = compute_nb_errors(model, train_input, train_target, mini_batch_size)
        frac_err = 100 * tot_err / train_input.size(0)
        print("{:5} {:>10.4f} {:8} {:11}%".format(e, sum_loss,tot_err, frac_err))
    print()

    #Testing
    tot_err = compute_nb_errors(model, test_input, test_target, mini_batch_size)
    frac_err = 100 * tot_err / test_input.size(0)

    print("TEST :")
    print("OUTPUT : ERROR RATE")
    print("{:6} {:11}%".format(tot_err, frac_err))
    print()
    return frac_err


    

def main():
    #Data setup
    # Parameter variables
    #Final statistics production
    nb_evaluation_iterations = 15
    eta = 5e-4
    mini_batch_size = 100

    train_input, train_target, test_input, test_target = None #generate data here
    eval_model(Basic_Net(), train_input, train_target,test_input, test_target, mini_batch_size, basic_eta)


        
if __name__ == "__main__":
    main()