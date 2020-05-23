
from torch import optim
import torch
from pcap import load_folds
from torch import nn
from torch.nn import functional as F
import numpy


class Basic_Net(nn.Module):
    def __init__(self):
        super(Basic_Net, self).__init__()
        self.conv1 = nn.Conv1d(1, 32, kernel_size=66, stride=66)
        self.conv2 = nn.Conv1d(32, 64, kernel_size=3)
        self.fc1 = nn.Linear(64 * 198, 500)
        self.fc2 = nn.Linear(500, 100)

    def forward(self, x):
        x = self.conv1(x)
        x = F.relu(F.max_pool1d(x, kernel_size = 2))
        x = F.relu(self.conv2(x))
        x = F.relu(self.fc1(x.view(-1, 64* 198)))
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


def eval_model(model, train_input, train_target,test_input, test_target, mini_batch_size, eta, nb_epochs):
    print(model)
    print("TRAINING")
    print("EPOCH : TOT_LOSS : OUTPUT : ERROR RATE")
    for e in range(0, nb_epochs):
        sum_loss = train_model(model, train_input, train_target, mini_batch_size, eta)
        tot_err = compute_nb_errors(model, train_input, train_target, mini_batch_size)
        frac_err = 100 * tot_err / train_input.size(0)
        print("{:5} {:>10.4f} {:8} {:11.4f}%".format(e, sum_loss,tot_err, frac_err))
    print()

    #Testing
    tot_err = compute_nb_errors(model, test_input, test_target, mini_batch_size)
    frac_err = 100 * tot_err / test_input.size(0)

    print("TEST :")
    print("OUTPUT : ERROR RATE")
    print("{:5} {:11.4f}%".format(tot_err, frac_err))
    print()
    return frac_err

def main():
    #Metaparameters
    eta = 0.005
    mini_batch_size = 100
    nb_epochs = 50

    #Parameters loading
    folds_data, folds_result, max_l = load_folds()

    error_rate = [0] * 10


    for j in range(10):
        train_input = (torch.tensor([folds_data[i] for i in range(10) if i != j]))/255.0
        train_target = torch.tensor([folds_result[i] for i in range(10) if i != j]) -1
        test_input = (torch.tensor(folds_data[j])) / 255.0
        test_target = torch.tensor(folds_result[j]) -1


        train_input = train_input.reshape(train_input.size(0) * train_input.size(1),1,train_input.size(2))
        train_target = train_target.reshape(train_target.size(0) * train_target.size(1))
        test_input = test_input.reshape(test_input.size(0),1,test_input.size(1))



        print ("ITERATION : " + str(j))
        error_rate[j] = eval_model(Basic_Net(), train_input, train_target,test_input, test_target, mini_batch_size, eta,nb_epochs)

    print("RESULT")
    print("MEAN_ERROR :    STD")
    print("{:10}% {:6}%".format(numpy.mean(error_rate), numpy.std(error_rate)))

        
if __name__ == "__main__":
    main()